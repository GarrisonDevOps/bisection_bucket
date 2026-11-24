# frozen_string_literal: true

module Types
  module Security
    class DependencyFirewallRuleTypeEnum < BaseEnum
      graphql_name 'DependencyFirewallRuleType'
      description 'Type of a dependency firewall policy rule.'

      DESCRIPTIONS = {
        'license' => 'Rule matching on package licenses.',
        'malicious' => 'Rule matching on packages flagged as malicious.',
        'risk_severity' => 'Rule matching on vulnerability counts per severity level.',
        'package_version' => 'Rule matching on an exact package name and version.'
      }.freeze

      # Derived from the model enum since that is the source of truth
      ::Security::DependencyFirewallPolicyRule.types.each_key do |type|
        value type.upcase, value: type,
          description: DESCRIPTIONS.fetch(type) { "Rule matching on #{type.tr('_', ' ')}." }
      end
    end
  end
end
