# frozen_string_literal: true

module Ci
  class DestroyOldPipelinesWorker
    include ApplicationWorker
    include CronjobChildWorker
    include LimitedCapacity::Worker

    data_consistency :sticky
    feature_category :continuous_integration
    urgency :low
    idempotent!

    RE_ENQUEUE_THRESHOLD = Ci::Pipelines::AutoCleanupService::BATCH_SIZE
    CONCURRENCY = 10
    LEASE_TIMEOUT = 10.minutes

    def perform_work(*)
      Project.find_by_id(cleanup_queue.fetch_next_project_id!).try do |project|
        with_context(project: project) do
          result = with_project_lease(project) do
            Ci::Pipelines::AutoCleanupService.new(project: project).execute
          end

          handle_result(project, result.payload) if result
        end
      end
    end

    def max_running_jobs
      CONCURRENCY
    end

    def remaining_work_count(*)
      cleanup_queue.size
    end

    private

    def cleanup_queue
      @cleanup_queue ||= Ci::RetentionPolicies::ProjectsCleanupQueue.instance
    end

    def with_project_lease(project)
      key = "#{self.class.name.underscore}:#{project.id}"
      uuid = Gitlab::ExclusiveLease.new(key, timeout: LEASE_TIMEOUT.to_i).try_obtain

      unless uuid
        log_extra_metadata_on_done(:lease_taken, true)
        return
      end

      begin
        yield
      ensure
        Gitlab::ExclusiveLease.cancel(key, uuid)
      end
    end

    def handle_result(project, payload)
      destroyed_count = payload[:destroyed_pipelines_size]
      skipped_count = payload[:skipped_pipelines_size]

      cleanup_queue.enqueue!(project) if destroyed_count + skipped_count >= RE_ENQUEUE_THRESHOLD

      log_extra_metadata_on_done(:removed_count, destroyed_count)
      log_extra_metadata_on_done(:skipped_count, skipped_count)
      log_extra_metadata_on_done(:project, project.full_path)
    end
  end
end
