# frozen_string_literal: true

module Security
  class DependencyFirewallPolicyRule < ApplicationRecord
    include PolicyRule

    self.table_name = 'dependency_firewall_policy_rules'

    # 1 was the removed `vulnerability` type and stays unassigned. 3 is left unassigned for the
    # in-flight `age` rule type: https://gitlab.com/gitlab-org/gitlab/-/work_items/592789
    enum :type, { license: 0, malicious: 2, risk_severity: 4, package_version: 5 }, prefix: true

    # Rule types whose findings carry an advisory severity. Single source for consumers that
    # branch on it; check_dep_fw_prevented_packages_severity_rule_type inlines these integers
    # because migrations cannot read application code.
    SEVERITY_CARRYING_TYPES = %w[risk_severity].freeze

    belongs_to :security_policy, class_name: 'Security::Policy', inverse_of: :dependency_firewall_policy_rules,
      optional: false

    validates :typed_content,
      json_schema: { filename: "dependency_firewall_policy_rule_content", size_limit: 64.kilobytes }

    validates :type, presence: true

    validates :rule_index, presence: true

    def self.severity_carrying_types
      SEVERITY_CARRYING_TYPES
    end
  end
end
