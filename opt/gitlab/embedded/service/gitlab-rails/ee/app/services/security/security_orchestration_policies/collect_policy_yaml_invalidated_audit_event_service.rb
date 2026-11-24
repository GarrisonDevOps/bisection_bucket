# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class CollectPolicyYamlInvalidatedAuditEventService < BaseSecurityPolicyAuditEventService
      def execute
        return if policy_configuration.policy_configuration_valid?

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      private

      def audit_context
        {
          name: 'security_policy_yaml_invalidated',
          author: policy_audit_event_author,
          scope: policy_management_project,
          target: policy_management_project,
          message: 'The policy YAML has been invalidated in the security policy project. ' \
            'Security policies will no longer be enforced.',
          additional_details: {
            security_policy_project_commit_sha: policy_commit&.sha,
            security_orchestration_policy_configuration_id: policy_configuration.id
          }
        }
      end
    end
  end
end
