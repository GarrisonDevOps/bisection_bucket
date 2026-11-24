# frozen_string_literal: true

module Approvals
  class WrappedRuleSet
    include Gitlab::Utils::StrongMemoize

    attr_reader :merge_request, :approval_rules

    APPROVAL_POLICY_REPORT_TYPES = [
      Security::ScanResultPolicy::SCAN_FINDING,
      Security::ScanResultPolicy::LICENSE_SCANNING,
      Security::ScanResultPolicy::ANY_MERGE_REQUEST
    ].freeze

    def self.wrap(merge_request, rules, report_type)
      if APPROVAL_POLICY_REPORT_TYPES.include?(report_type.to_s)
        ScanFindingWrappedRuleSet.new(merge_request, rules)
      else
        WrappedRuleSet.new(merge_request, rules)
      end
    end

    def initialize(merge_request, approval_rules)
      @merge_request = merge_request
      @approval_rules = approval_rules
    end

    def wrapped_rules
      strong_memoize(:wrapped_rules) do
        approval_rules.map do |rule|
          ApprovalWrappedRule.wrap(merge_request, rule)
        end
      end
    end
  end
end
