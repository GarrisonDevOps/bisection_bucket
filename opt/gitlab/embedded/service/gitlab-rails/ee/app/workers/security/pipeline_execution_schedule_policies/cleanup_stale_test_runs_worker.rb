# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicies
    class CleanupStaleTestRunsWorker
      include ApplicationWorker
      include CronjobQueue

      idempotent!
      data_consistency :sticky
      feature_category :security_policy_management

      BATCH_SIZE = 100
      MAX_BATCHES = 10
      PENDING_ERROR_MESSAGE = 'Pipeline creation timed out'
      RUNNING_ERROR_MESSAGE = 'Pipeline execution timed out'

      def perform
        total_cleaned = 0

        MAX_BATCHES.times do
          batch_size, cleaned = process_batch
          total_cleaned += cleaned

          break if batch_size < BATCH_SIZE
        end

        log_extra_metadata_on_done(:cleaned_count, total_cleaned)
      end

      private

      def process_batch
        test_run_model = ::Security::ScheduledPipelineExecutionPolicyTestRun

        stale_test_runs = test_run_model.stale.preload_project.limit(BATCH_SIZE).to_a
        return [0, 0] if stale_test_runs.empty?

        pending_runs, running_runs = stale_test_runs.partition(&:pending?)

        pending_count = test_run_model.mark_as_failed(
          ids: pending_runs.map(&:id),
          error_message: PENDING_ERROR_MESSAGE,
          expected_state: :pending
        )
        running_count = test_run_model.mark_as_failed(
          ids: running_runs.map(&:id),
          error_message: RUNNING_ERROR_MESSAGE,
          expected_state: :running
        )

        trigger_subscriptions(stale_test_runs)

        [stale_test_runs.size, pending_count + running_count]
      end

      def trigger_subscriptions(test_runs)
        test_runs.each do |test_run|
          with_context(project: test_run.project) do
            ::GraphqlTriggers.security_policy_schedule_test_run_updated(test_run)
          end
        end
      end
    end
  end
end
