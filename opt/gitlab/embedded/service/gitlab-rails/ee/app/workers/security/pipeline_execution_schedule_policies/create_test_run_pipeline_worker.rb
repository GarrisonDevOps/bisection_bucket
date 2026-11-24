# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicies
    class CreateTestRunPipelineWorker
      include ApplicationWorker

      feature_category :security_policy_management
      idempotent!
      deduplicate :until_executed
      urgency :low
      data_consistency :delayed
      defer_on_database_health_signal :gitlab_main, [:scheduled_pipeline_execution_policy_test_runs]
      sidekiq_options retry: 3

      def perform(test_run_id)
        test_run = ::Security::ScheduledPipelineExecutionPolicyTestRun.find_by_id(test_run_id)
        return unless test_run&.pending?

        unless test_run.claim_for_pipeline_creation
          log_info(test_run_id: test_run.id, message: 'Failed to claim pending test run')
          return
        end

        execute_pipeline(test_run)
      end

      private

      def execute_pipeline(test_run)
        result = ::Security::PipelineExecutionPolicies::CreateScheduledPipelineService.new(
          project: test_run.project,
          ci_content: test_run.security_policy.content['content'],
          policy: test_run.security_policy
        ).execute

        if result.success?
          test_run.update!(pipeline: result.payload, state: :running)
        else
          log_error(test_run_id: test_run.id, message: 'Pipeline creation failed', error_message: result.message)
          test_run.mark_as_failed!(result.message)
        end

        broadcast_test_run_update(test_run)
      rescue StandardError => e
        log_error(test_run_id: test_run.id, message: 'Unexpected error during pipeline creation',
          error_message: e.message)
        test_run.mark_as_failed!('Pipeline creation failed - an orphaned pipeline may exist')
        broadcast_test_run_update(test_run)

        raise
      end

      def broadcast_test_run_update(test_run)
        ::GraphqlTriggers.security_policy_schedule_test_run_updated(test_run.reset)
      end

      def log_info(attributes)
        ::Gitlab::AppLogger.info(build_structured_payload_labkit(**attributes))
      end

      def log_error(attributes)
        ::Gitlab::AppLogger.error(build_structured_payload_labkit(**attributes))
      end
    end
  end
end
