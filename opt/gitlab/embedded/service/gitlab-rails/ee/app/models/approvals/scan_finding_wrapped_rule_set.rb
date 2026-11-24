# frozen_string_literal: true

module Approvals
  class ScanFindingWrappedRuleSet < WrappedRuleSet
    extend ::Gitlab::Utils::Override

    override :wrapped_rules
    def wrapped_rules
      strong_memoize(:wrapped_rules) do
        grouped_merge_request_rules.map do |_, merge_request_rules|
          least_approved_rule(merge_request_rules)
        end
      end
    end

    private

    def grouped_merge_request_rules
      approval_rules.group_by do |rule|
        [
          rule.security_orchestration_policy_configuration_id,
          rule.orchestration_policy_idx,
          rule.approval_policy_action_idx
        ]
      end
    end

    def least_approved_rule(merge_request_rules)
      wrapped = merge_request_rules.map do |rule|
        ApprovalWrappedRule.wrap(merge_request, rule)
      end
      wrapped.find { |rule| !rule.approved? } || wrapped.first
    end
  end
end
