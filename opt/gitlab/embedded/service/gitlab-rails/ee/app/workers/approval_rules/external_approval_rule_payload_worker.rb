# frozen_string_literal: true

module ApprovalRules
  class ExternalApprovalRulePayloadWorker
    include ApplicationWorker

    data_consistency :always

    sidekiq_options retry: 3
    idempotent!

    feature_category :security_policy_management

    def perform(external_status_check_id, data)
      external_status_check = MergeRequests::ExternalStatusCheck.find(external_status_check_id)

      ExternalStatusChecks::DispatchService.new(external_status_check, data).execute
    end
  end
end
