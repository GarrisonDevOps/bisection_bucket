# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class AuditWarnModeGroupProtectedBranchesOverridesGroupWorker
      include ApplicationWorker

      # This worker is marked as idempotent to enable deduplication.
      # While not strictly idempotent (the policy.yml state may change between runs,
      # leading to different outcomes), deduplication prevents duplicate audit events
      # when the worker is retried with the same group.
      idempotent!
      data_consistency :sticky
      feature_category :security_policy_management

      def perform(group_id)
        group = Group.find_by_id(group_id) || return

        return unless eligible_to_run?(group)

        Security::ScanResultPolicies::AuditWarnModeGroupProtectedBranchesOverridesService
          .new(group: group)
          .execute
      end

      private

      def eligible_to_run?(group)
        !(group.archived? || group.pending_delete? || group.protected_branches.none?)
      end
    end
  end
end
