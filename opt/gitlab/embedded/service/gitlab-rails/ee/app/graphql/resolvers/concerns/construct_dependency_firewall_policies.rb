# frozen_string_literal: true

module ConstructDependencyFirewallPolicies
  extend ActiveSupport::Concern
  include ConstructSecurityPoliciesSharedAttributes

  def construct_dependency_firewall_policy(policy, with_policy_attributes = false)
    policy_attributes = base_policy_attributes(policy)
    policy_hash = {
      name: policy[:name],
      description: policy[:description],
      edit_path: edit_path(policy, :dependency_firewall_policy),
      enabled: policy[:enabled],
      policy_scope: policy_scope(policy[:policy_scope]),
      yaml: YAML.dump(
        policy.slice(*POLICY_YAML_ATTRIBUTES, :rules, :enforcement_type, :bypass_settings).deep_stringify_keys
      ),
      config: policy[:config],
      csp: policy[:csp],
      type: policy[:type],
      policy_index: policy[:policy_index]
    }

    policy_hash.merge(policy_specific_attributes(policy[:type], policy_attributes, with_policy_attributes))
  end
end
