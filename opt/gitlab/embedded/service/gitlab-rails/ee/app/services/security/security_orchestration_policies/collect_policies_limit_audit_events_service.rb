# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class CollectPoliciesLimitAuditEventsService < BaseSecurityPolicyAuditEventService
      def execute
        OrchestrationPolicyConfiguration::AVAILABLE_POLICY_TYPES.each do |policy_type|
          policy_limit = policy_configuration.policy_limit_by_type(policy_type)
          policies = policy_configuration.policy_by_type(policy_type)
          enabled_policies = filter_enabled_policies(policies)

          next if enabled_policies.count <= policy_limit

          ::Gitlab::Audit::Auditor.audit(audit_context(policy_type, policy_limit, enabled_policies))
        end
      end

      private

      def filter_enabled_policies(policies)
        policies.select { |policy| policy[:enabled] }
      end

      def policy_type_name(policy_type)
        policy_configuration.policy_type_name_by_type(policy_type)
      end

      def audit_context(policy_type, policy_limit, policies)
        policy_names = policies.pluck(:name) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- pluck used on hash
        {
          name: 'security_policy_limit_exceeded',
          author: policy_audit_event_author,
          scope: policy_management_project,
          target: policy_management_project,
          message: audit_message(policy_type_name(policy_type), policy_limit),
          additional_details: {
            policy_type: policy_type,
            policy_type_limit: policy_limit,
            policies_count: policies.count,
            active_skipped_policies_count: policies.count - policy_limit,
            active_policies_names: policy_names.first(policy_limit),
            active_skipped_policies_names: policy_names.drop(policy_limit),
            security_policy_project_commit_sha: policy_commit&.sha,
            security_orchestration_policy_configuration_id: policy_configuration.id,
            security_policy_configured_at: policy_configuration.configured_at
          }
        }
      end

      def audit_message(type_name, policy_limit)
        "Policies limit exceeded for '#{type_name}' type. " \
          "Only the first #{policy_limit} enabled policies will be applied"
      end
    end
  end
end
