# frozen_string_literal: true

module Security
  class ScanExecutionPolicyRule < ApplicationRecord
    include PolicyRule

    self.table_name = 'scan_execution_policy_rules'

    enum :type, { pipeline: 0, schedule: 1 }, prefix: true

    belongs_to :security_policy, class_name: 'Security::Policy', inverse_of: :scan_execution_policy_rules

    validates :typed_content, json_schema: { filename: "scan_execution_policy_rule_content" }
  end
end
