# frozen_string_literal: true

module Ai
  class FlowScheduleWorker # rubocop:disable Scalability/IdempotentWorker -- cron dispatcher, not idempotent by nature
    include ApplicationWorker

    data_consistency :sticky

    include CronjobQueue
    include ::Gitlab::ExclusiveLeaseHelpers

    LOCK_RETRY = 3
    LOCK_TTL = 5.minutes
    DELAY = 7.seconds
    BATCH_SIZE = 500

    feature_category :dap_triggers
    worker_resource_boundary :cpu

    def perform
      in_lock(lock_key, **lock_params) do
        ::Ai::FlowSchedule
          .select(:id, :project_id)
          .runnable_schedules
          .preload_project_route
          .each_batch(of: BATCH_SIZE) do |schedules, index|
            enqueue_run_workers(schedules, index)
          end
      end
    end

    private

    def lock_key
      self.class.name.underscore
    end

    def lock_params
      {
        ttl: LOCK_TTL,
        retries: LOCK_RETRY
      }
    end

    def enqueue_run_workers(schedules, batch_index)
      enabled_schedules = schedules.to_a.select { |schedule| Feature.enabled?(:ai_flow_schedules, schedule.project) }
      return if enabled_schedules.empty?

      # each_batch yields a 1-based index, so the first batch runs without delay
      ::Ai::RunFlowScheduleWorker.bulk_perform_in_with_contexts(
        [1, (batch_index - 1) * DELAY].max,
        enabled_schedules,
        arguments_proc: ->(schedule) { [schedule.id, { 'scheduling' => true }] },
        context_proc: ->(schedule) { { project: schedule.project } }
      )
    end
  end
end
