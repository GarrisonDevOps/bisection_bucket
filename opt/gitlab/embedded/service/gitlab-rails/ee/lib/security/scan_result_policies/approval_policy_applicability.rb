# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module ApprovalPolicyApplicability
      module_function

      # An approval rule can be linked to its policy by either column - legacy rules carry only
      # scan_result_policy_id. Either link is enough to block the merge request in
      # CheckSecurityPolicyViolationsService, so both have to be checked.
      def applicable?(project)
        rules = project.approval_rules.report_approver

        ::Security::PolicyAvailability.any_available?(project) &&
          rules.with_approval_policy_rule.or(rules.with_scan_result_policy_read).exists?
      end
    end
  end
end
