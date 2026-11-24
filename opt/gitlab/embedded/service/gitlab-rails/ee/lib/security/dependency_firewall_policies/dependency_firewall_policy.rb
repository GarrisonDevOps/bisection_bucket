# frozen_string_literal: true

module Security
  module DependencyFirewallPolicies
    class DependencyFirewallPolicy < Security::BaseSecurityPolicy
      include Gitlab::Utils::StrongMemoize

      def enforcement_type
        policy_content[:enforcement_type]
      end

      def rules
        # Carry the persisted rule's id through so a matched rule can be attributed back to its DB
        # row (used by enforcement activity stats), without changing evaluation logic.
        policy_rules = policy_record
                         .undeleted_dependency_firewall_policy_rules
                         .map do |rule|
                           rule.typed_content.deep_symbolize_keys.merge(rule_id: rule.id)
                         end

        ::Security::DependencyFirewallPolicies::Rules.new(policy_rules)
      end
      strong_memoize_attr :rules

      def bypass_settings
        Security::DependencyFirewallPolicies::BypassSettings.new(policy_content[:bypass_settings])
      end
      strong_memoize_attr :bypass_settings

      def policy_content
        policy_record.policy_content
      end
    end
  end
end
