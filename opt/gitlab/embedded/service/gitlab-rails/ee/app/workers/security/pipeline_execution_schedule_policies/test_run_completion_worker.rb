# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicies
    class TestRunCompletionWorker
      include Gitlab::EventStore::Subscriber

      feature_category :security_policy_management
      data_consistency :sticky
      idempotent!
      deduplicate :until_executing, including_scheduled: true

      def handle_event(event)
        pipeline_id = event.data[:pipeline_id]
        status = event.data[:status]

        test_run = ::Security::ScheduledPipelineExecutionPolicyTestRun.for_pipeline_id(pipeline_id).first
        unless test_run
          Gitlab::AppLogger.error(build_structured_payload_labkit(message: 'Test run not found for pipeline',
            pipeline_id: pipeline_id))
          return
        end

        if status == 'failed'
          return if test_run.failed?

          test_run.mark_as_failed!
        else
          return if test_run.complete?

          test_run.update!(state: :complete)
        end

        ::GraphqlTriggers.security_policy_schedule_test_run_updated(test_run)
      end
    end
  end
end
