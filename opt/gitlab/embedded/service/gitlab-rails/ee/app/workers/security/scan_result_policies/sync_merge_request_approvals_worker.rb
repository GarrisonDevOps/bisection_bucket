# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncMergeRequestApprovalsWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      data_consistency :sticky
      sidekiq_options retry: true
      urgency :low

      feature_category :security_policy_management

      def perform(pipeline_id, merge_request_id)
        pipeline = Ci::Pipeline.find_by_id(pipeline_id)
        return unless pipeline

        merge_request = MergeRequest.find_by_id(merge_request_id)
        return unless merge_request

        UpdateApprovalsService.new(merge_request: merge_request, pipeline: pipeline).execute
      end
    end
  end
end
