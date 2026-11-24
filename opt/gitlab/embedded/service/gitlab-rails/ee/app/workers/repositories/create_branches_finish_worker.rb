# frozen_string_literal: true

module Repositories
  class CreateBranchesFinishWorker # rubocop:disable Scalability/IdempotentWorker -- reads mutable Redis state
    include ApplicationWorker
    include Repositories::MirrorUpdateMetrics

    data_consistency :delayed
    feature_category :source_code_management
    urgency :low
    sidekiq_options dead: false, retry: 6, status_expiration: Gitlab::Import::StuckImportJob::IMPORT_JOBS_EXPIRATION

    defer_on_database_health_signal :gitlab_main, []

    POLL_INTERVAL = 1.minute
    BLOCKING_WAIT_TIME = 5
    TIMEOUT_DURATION = 1.hour
    TIMEOUT_ERROR_MESSAGE = 'Branch creation timed out'
    ERRORS_CACHE_KEY = 'mirror-branch-create:%{waiter_key}:errors'

    def self.cache_key(waiter_key)
      format(ERRORS_CACHE_KEY, waiter_key: waiter_key)
    end

    def self.add_error(waiter_key, branch_name, message)
      Gitlab::Cache::Import::Caching.hash_add(cache_key(waiter_key), branch_name, message)
    end

    def perform(project_id, waiter_key, jobs_remaining, excess_branches_count = 0, last_progress_at = Time.current.to_i)
      project = Project.find_by_id(project_id)

      unless project
        Gitlab::JobWaiter.delete_key(waiter_key)
        expire_errors_cache(waiter_key)
        return
      end

      waiter = Gitlab::JobWaiter.new(jobs_remaining, waiter_key)
      waiter.wait(BLOCKING_WAIT_TIME)

      remaining = waiter.jobs_remaining
      last_progress_at = Time.current.to_i if remaining < jobs_remaining

      if remaining == 0
        finalize(project, waiter_key, excess_branches_count)
      elsif timeout_reached?(last_progress_at)
        finalize(project, waiter_key, excess_branches_count, non_branch_errors: [TIMEOUT_ERROR_MESSAGE])
      else
        self.class.perform_in(
          POLL_INTERVAL,
          project_id, waiter_key, remaining, excess_branches_count, last_progress_at
        )
      end
    end

    private

    def finalize(project, waiter_key, excess_branches_count, non_branch_errors: [])
      Gitlab::JobWaiter.delete_key(waiter_key)
      import_state = project.import_state
      errors = cached_errors(waiter_key)
      error_messages = errors.values

      if excess_branches_count > 0
        error_messages << format(
          "Mirror update could not create all branches: %{excess_branches_count} branches exceeded the limit " \
            "and were not created. They will be synced in subsequent mirror updates.",
          excess_branches_count: excess_branches_count
        )
      end

      error_messages.concat(non_branch_errors.compact)

      if error_messages.blank?
        import_state.finish
        log_mirror_update_finished(project, async_branch_creation: true)
      else
        import_state.mark_as_failed(error_messages.join("\n\n"))
      end

    ensure
      expire_errors_cache(waiter_key)
    end

    def timeout_reached?(last_progress_at)
      Time.current.to_i - last_progress_at >= TIMEOUT_DURATION.to_i
    end

    def cached_errors(waiter_key)
      cache_key = self.class.cache_key(waiter_key)
      Gitlab::Cache::Import::Caching.values_from_hash(cache_key)
    end

    def expire_errors_cache(waiter_key)
      cache_key = self.class.cache_key(waiter_key)
      Gitlab::Cache::Import::Caching.expire(cache_key, Gitlab::Cache::Import::Caching::SHORTER_TIMEOUT)
    end
  end
end
