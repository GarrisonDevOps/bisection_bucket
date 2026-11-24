# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class BranchDeletionBypassAuditor
      def initialize(security_policy:, container:, user:)
        @security_policy = security_policy
        @container = container
        @user = user
      end

      def log_service_account_bypass(service_account_id)
        audit_details = {
          bypass_type: :service_account,
          service_account_id: service_account_id,
          action: :branch_deletion
        }

        log_bypass_event(
          audit_name: 'security_policy_service_account_branch_deletion_bypass',
          identifier: service_account_id,
          additional_details: audit_details
        )
      end

      def log_access_token_bypass(token_ids)
        audit_details = {
          bypass_type: :access_token,
          access_token_ids: Array.wrap(token_ids),
          action: :branch_deletion
        }

        log_bypass_event(
          audit_name: 'security_policy_access_token_branch_deletion_bypass',
          identifier: token_ids,
          additional_details: audit_details
        )
      end

      private

      attr_reader :security_policy, :container, :user

      def log_bypass_event(audit_name:, identifier:, additional_details:)
        message = build_audit_message(additional_details[:bypass_type], identifier)

        Gitlab::Audit::Auditor.audit(
          name: audit_name,
          author: user,
          scope: security_policy.security_policy_management_project,
          target: security_policy,
          message: message,
          additional_details: {
            container_id: container.id,
            container_type: container.class.name,
            security_policy_name: security_policy.name,
            security_policy_id: security_policy.id
          }.merge(additional_details)
        )
      end

      def build_audit_message(bypass_type, identifier)
        container_label = container.is_a?(Group) ? 'group' : 'project'
        <<~MSG.squish
          Protected branch deletion for #{container_label} '#{container.full_path}'
          has been bypassed by a #{bypass_type} with ID: #{identifier}
        MSG
      end
    end
  end
end
