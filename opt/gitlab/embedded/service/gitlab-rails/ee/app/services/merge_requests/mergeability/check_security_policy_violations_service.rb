# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckSecurityPolicyViolationsService < CheckBaseService
      set_identifier :security_policy_violations
      set_failure_explanation N_('All security policy violations must be resolved.')
      set_description 'Checks whether the security policies are satisfied'

      RESYNC_DEBOUNCE_TIMEOUT = 1.minute

      def execute
        return inactive unless ::Security::PolicyAvailability.any_available?(merge_request.project)

        if approval_rules_out_of_sync?
          schedule_approval_rules_resync
          return checking
        end

        return inactive unless merge_request_has_approval_policy_rules?

        return checking if merge_request.running_scan_result_policy_violations.any?

        # When the MR is approved, it is considered to 'override' the violations
        if failed_violations? && !merge_request.approved?
          failure
        elsif policy_violations_dismissed? || security_policy_bypassed?
          warning
        else
          success
        end
      end

      def skip?
        params[:skip_security_policy_check].present?
      end

      def cacheable?
        false
      end

      private

      def approval_rules_out_of_sync?
        # `mergeabilityChecks` runs every check, so this is reached for merged and closed MRs too
        return false unless merge_request.open?

        merge_request.missing_policy_approval_rules?
      end

      def schedule_approval_rules_resync
        return unless resync_lease.try_obtain

        Gitlab::AppJsonLogger.info(
          event: 'security_policy_approval_rules_desync_detected',
          merge_request_id: merge_request.id,
          Labkit::Fields::GL_PROJECT_PATH => merge_request.project.full_path
        )

        ::Security::ScanResultPolicies::ResyncMergeRequestRulesWorker.perform_async(merge_request.id)
      end

      def resync_lease
        Gitlab::ExclusiveLease.new(
          "security_policy_approval_rules_resync:#{merge_request.id}",
          timeout: RESYNC_DEBOUNCE_TIMEOUT.to_i
        )
      end

      def merge_request_has_approval_policy_rules?
        approval_policy_rules_present? || merge_request.scan_result_policy_reads_through_approval_rules.any?
      end

      def approval_policy_rules_present?
        approval_rules = merge_request.approval_rules
        # List endpoints preload approval_rules, so a scope here would be one extra query per MR
        return approval_rules.any? { |rule| rule.approval_policy_rule_id.present? } if approval_rules.loaded?

        approval_rules.with_approval_policy_rule.any?
      end

      def failed_violations?
        # List endpoints preload every violation, so filtering them saves a query per merge request
        violations = preloaded_violations
        return violations.any?(&:failed?) if violations

        merge_request.failed_scan_result_policy_violations.any?
      end

      def policy_violations_dismissed?
        return false if preloaded_violations && preloaded_violations.empty?

        violations_with_dismissals = merge_request.scan_result_policy_violations
                                                  .with_security_policy_dismissal

        return false if violations_with_dismissals.empty?

        violations_with_dismissals.any?(&:dismissed?)
      end

      def security_policy_bypassed?
        return false unless project_has_bypass_policies?

        merge_request.security_policies_with_bypass_settings.any? do |policy|
          policy.merge_request_bypassed?(merge_request)
        end
      end

      def preloaded_violations
        violations = merge_request.scan_result_policy_violations
        violations if violations.loaded?
      end

      # Same SQL for every merge request in a project, so list pages hit the query cache
      def project_has_bypass_policies?
        merge_request.project.approval_policies.with_bypass_settings.exists?
      end
    end
  end
end
