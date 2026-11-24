# frozen_string_literal: true

module MergeRequests
  class SyncCodeOwnerApprovalRulesWorker
    include ApplicationWorker

    data_consistency :always

    sidekiq_options retry: 3

    feature_category :source_code_management
    urgency :high
    deduplicate :until_executed
    idempotent!

    def perform(merge_request_id, params = {})
      merge_request = MergeRequest.find_by_id(merge_request_id)
      return unless merge_request

      params = params.with_indifferent_access

      merge_request.approval_state.temporarily_unapprove! if params[:expire_unapproved_key]

      ::MergeRequests::SyncCodeOwnerApprovalRules.new(merge_request, params).execute
    end
  end
end
