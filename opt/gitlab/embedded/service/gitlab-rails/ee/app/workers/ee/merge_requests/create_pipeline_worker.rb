# frozen_string_literal: true

module EE
  module MergeRequests
    module CreatePipelineWorker
      extend ::Gitlab::Utils::Override

      override :after_perform
      def after_perform(merge_request)
        super

        return unless ::Security::PolicyAvailability.any_available?(merge_request.project)

        # When async pipeline creation is enabled, `schedule_policy_synchronization`
        # skips enqueuing pipeline-dependent workers because `diff_head_pipeline` may
        # not be set yet. This hook enqueues them once pipeline creation finishes.
        pipeline = merge_request.diff_head_pipeline

        if pipeline
          ::Ci::SyncReportsToReportApprovalRulesWorker.perform_async(pipeline.id)
          ::Security::ScanResultPolicies::SyncMergeRequestApprovalsWorker.perform_async(pipeline.id, merge_request.id)
          ::Security::UnenforceablePolicyRulesPipelineNotificationWorker.perform_async(pipeline.id)
        else
          ::Security::UnenforceablePolicyRulesNotificationWorker.perform_async(merge_request.id)
        end
      end
    end
  end
end
