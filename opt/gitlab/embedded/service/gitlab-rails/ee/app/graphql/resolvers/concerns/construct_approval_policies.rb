# frozen_string_literal: true

module ConstructApprovalPolicies
  extend ActiveSupport::Concern
  include Security::SecurityOrchestrationPolicies::DeprecatedPropertiesChecker
  include ConstructSecurityPoliciesSharedAttributes

  def construct_scan_result_policies(policies)
    policies.map do |policy|
      construct_scan_result_policy(policy)
    end
  end

  def construct_scan_result_policy(policy, with_policy_attributes = false)
    approvers = approvers(policy)

    policy_attributes = base_policy_attributes(policy).merge(
      action_approvers: approvers[:approvers],
      all_group_approvers: approvers[:all_groups],
      custom_roles: approvers[:custom_roles],
      deprecated_properties: deprecated_properties(policy),
      enforcement_type: policy[:enforcement_type],
      role_approvers: approvers[:roles],
      user_approvers: approvers[:users]
    )

    policy_hash = {
      name: policy[:name],
      description: policy[:description],
      edit_path: edit_path(policy, :approval_policy),
      enabled: policy[:enabled],
      policy_scope: policy_scope(policy[:policy_scope]),
      yaml: YAML.dump(policy.slice(*POLICY_YAML_ATTRIBUTES, :actions, :rules, :approval_settings,
        :fallback_behavior, :metadata, :policy_tuning, :bypass_settings, :enforcement_type).deep_stringify_keys),
      config: policy[:config],
      csp: policy[:csp],
      type: policy[:type],
      policy_index: policy[:policy_index]
    }

    policy_hash.merge(policy_specific_attributes(policy[:type], policy_attributes, with_policy_attributes))
  end

  def approvers(policy)
    Security::SecurityOrchestrationPolicies::FetchPolicyApproversService
      .new(policy: policy, container: container, current_user: current_user)
      .execute
  end
end
