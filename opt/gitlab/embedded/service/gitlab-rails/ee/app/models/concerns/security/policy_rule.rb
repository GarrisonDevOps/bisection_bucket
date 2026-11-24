# frozen_string_literal: true

module Security
  module PolicyRule
    extend ActiveSupport::Concern

    SUPPORTED_POLICY_TYPES = [
      :approval_policy,
      :scan_execution_policy,
      :vulnerability_management_policy,
      :dependency_firewall_policy
    ].freeze

    def self.for_policy_type(policy_type)
      case policy_type
      when :approval_policy then Security::ApprovalPolicyRule
      when :scan_execution_policy then Security::ScanExecutionPolicyRule
      when :vulnerability_management_policy then Security::VulnerabilityManagementPolicyRule
      when :dependency_firewall_policy then Security::DependencyFirewallPolicyRule
      else raise ArgumentError, "unrecognized policy_type"
      end
    end

    included do
      self.inheritance_column = :_type_disabled

      scope :deleted, -> { where('rule_index < 0') }
      scope :undeleted, -> { where('rule_index >= 0') }
    end

    class_methods do
      def attributes_from_rule_hash(rule_hash, policy_configuration)
        {
          type: rule_hash[:type],
          content: rule_hash.without(:type),
          security_policy_management_project_id: policy_configuration.security_policy_management_project_id
        }
      end
    end

    def typed_content
      content.deep_stringify_keys.merge("type" => type)
    end
  end
end
