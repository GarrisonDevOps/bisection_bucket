# frozen_string_literal: true

module ConstructScanExecutionPolicies
  extend ActiveSupport::Concern
  include Security::SecurityOrchestrationPolicies::DeprecatedPropertiesChecker
  include ConstructSecurityPoliciesSharedAttributes

  def construct_scan_execution_policies(policies)
    policies.map do |policy|
      construct_scan_execution_policy(policy)
    end
  end

  def construct_scan_execution_policy(policy, with_policy_attributes = false)
    policy_attributes = base_policy_attributes(policy).merge(
      deprecated_properties: deprecated_properties(policy)
    )

    policy_hash = {
      name: policy[:name],
      description: policy[:description],
      edit_path: edit_path(policy, :scan_execution_policy),
      enabled: policy[:enabled],
      policy_scope: policy_scope(policy[:policy_scope]),
      yaml: YAML.dump(policy.slice(*POLICY_YAML_ATTRIBUTES, :actions, :rules, :metadata,
        :skip_ci).deep_stringify_keys),
      config: policy[:config],
      csp: policy[:csp],
      type: policy[:type],
      policy_index: policy[:policy_index]
    }

    policy_hash.merge(policy_specific_attributes(policy[:type], policy_attributes, with_policy_attributes))
  end
end
