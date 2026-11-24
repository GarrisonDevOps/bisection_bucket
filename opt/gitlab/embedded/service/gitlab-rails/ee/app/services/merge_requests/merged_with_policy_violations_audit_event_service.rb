# frozen_string_literal: true

module MergeRequests
  class MergedWithPolicyViolationsAuditEventService < BasePolicyViolationsAuditEventService
    private

    def eligible_to_run?
      merge_request.merged?
    end

    def audit_event_name
      'security_policy_merge_request_merged_with_policy_violations'
    end

    def audit_message
      "Merge request (#{merge_request_reference}) was merged with security policy violation(s)"
    end

    def audit_author
      merge_request.metrics.merged_by || unknown_user
    end

    def audit_details(violations)
      super.merge(
        merged_at: merge_request.merged_at,
        policy_approval_rules: policy_approval_rules(violations)
      )
    end

    def policy_approval_rules(violations)
      rules = find_approval_merge_request_rules(violations)
      return [] if rules.blank?

      Approvals::WrappedRuleSet.new(merge_request, rules).wrapped_rules.map do |rule|
        {
          name: rule.name,
          report_type: rule.report_type,
          approvals_required: rule.approvals_required,
          approved: rule.approved?,
          approved_approvers: rule.approved_approvers.map(&:username).sort,
          invalid_rule: rule.invalid_rule?,
          fail_open: rule.fail_open?
        }
      end
    end

    def find_approval_merge_request_rules(violations)
      violations.flat_map do |violation|
        violation.approval_policy_rule&.approval_merge_request_rules&.for_merge_requests(merge_request.id) || []
      end
    end
  end
end
