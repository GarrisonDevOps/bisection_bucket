# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class CreateWarnModeApprovalAuditEventsWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :sticky
      idempotent!
      feature_category :security_policy_management

      concurrency_limit -> { 200 }

      def self.dispatch?(event)
        merge_request = MergeRequest.find_by_id(event.data[:merge_request_id])

        return false unless merge_request

        project = merge_request.project

        ::Security::PolicyAvailability.any_available?(project)
      end

      def handle_event(event)
        merge_request_id, user_id = event.data.values_at(:merge_request_id, :current_user_id)
        merge_request = MergeRequest.find_by_id(merge_request_id) || return
        project = merge_request.project

        return unless ::Security::PolicyAvailability.any_available?(project)
        return unless merge_request.open?

        user = User.find_by_id(user_id) || return

        Security::ScanResultPolicies::CreateWarnModeApprovalAuditEventService
          .new(merge_request, user)
          .execute
      end
    end
  end
end
