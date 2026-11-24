# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncPreexistingStatesApprovalRulesService
      include VulnerabilityStatesHelper
      include ::Security::ScanResultPolicies::PolicyLogger

      def initialize(merge_request)
        @merge_request = merge_request
      end

      def execute
        return if merge_request.merged?

        approval_rules = merge_request
          .approval_rules
          .scan_finding
          .including_scan_result_policy_read
          .including_approval_policy_rule

        rules_with_preexisting_states = approval_rules.reject do |rule|
          include_newly_detected?(rule)
        end

        return unless rules_with_preexisting_states.any?

        evaluate_rules(rules_with_preexisting_states)
        evaluation.save
      end

      private

      attr_reader :merge_request

      delegate :project, to: :merge_request, private: true

      def evaluate_rules(approval_rules)
        log_message('Evaluating pre_existing scan_finding rules from approval policies')
        approval_rules.each do |rule|
          rule_violated, violation_data = preexisting_findings_count_violated?(rule)

          if rule_violated
            log_message('Updating MR approval rule with pre_existing states',
              reason: 'pre_existing scan_finding rule violated',
              approval_rule_id: rule.id, approval_rule_name: rule.name)
            evaluation.fail!(rule, data: violation_data)
          else
            evaluation.pass!(rule)
          end
        end
      end

      def preexisting_findings_count_violated?(approval_rule)
        if approval_rule.scanner_configurations.present?
          return preexisting_grouped_findings_count_violated?(approval_rule)
        end

        vulnerabilities = vulnerabilities(approval_rule)

        violated = vulnerabilities.count > approval_rule.vulnerabilities_allowed
        [violated, build_violation_data(vulnerabilities)]
      end

      def preexisting_grouped_findings_count_violated?(approval_rule)
        grouped_results = grouped_vulnerabilities(approval_rule)

        return [false, nil] if grouped_results.blank?

        all_vulnerabilities_ids = []
        violated = false

        grouped_results.each do |group_result|
          allowed_count = group_result.vulnerabilities_allowed || approval_rule.vulnerabilities_allowed
          vulnerability_ids = group_result.vulnerabilities.pluck_primary_key
          next if vulnerability_ids.size <= allowed_count

          all_vulnerabilities_ids.concat(vulnerability_ids)
          violated = true
        end

        all_vulnerabilities_ids.uniq!

        combined_vulns = if all_vulnerabilities_ids.any?
                           project.vulnerabilities.id_in(all_vulnerabilities_ids)
                         else
                           project.vulnerabilities.none
                         end

        [violated, build_violation_data(combined_vulns)]
      end

      def grouped_vulnerabilities(approval_rule)
        service_params = {
          vulnerabilities_allowed: approval_rule.vulnerabilities_allowed,
          state: states_without_newly_detected(approval_rule.vulnerability_states),
          severity: approval_rule.severity_levels,
          scanner_configurations: approval_rule.scanner_configurations,
          vulnerability_age: approval_rule.approval_policy_source&.vulnerability_age
        }
        ::Security::ScanResultPolicies::GroupedVulnerabilitiesEvaluator.new(project, service_params).grouped_results
      end

      def vulnerabilities(approval_rule)
        finder_params = {
          limit: approval_rule.vulnerabilities_allowed + 1,
          state: states_without_newly_detected(approval_rule.vulnerability_states),
          severity: approval_rule.severity_levels,
          report_type: approval_rule.scanners,
          fix_available: approval_rule.vulnerability_attribute_fix_available,
          false_positive: approval_rule.vulnerability_attribute_false_positive,
          vulnerability_age: approval_rule.approval_policy_source&.vulnerability_age,
          known_exploited: approval_rule.vulnerability_attribute_known_exploited,
          epss_score: approval_rule.vulnerability_attribute_epss_score,
          enrichment_data_unavailable_action: approval_rule.vulnerability_attribute_enrichment_data_unavailable_action
        }
        ::Security::ScanResultPolicies::VulnerabilitiesFinder.new(project, finder_params).execute
      end

      def log_message(message, **attributes)
        log_policy_evaluation('update_approvals', message,
          project: project, merge_request_id: merge_request.id, merge_request_iid: merge_request.iid, **attributes)
      end

      def evaluation
        @evaluation ||= Security::SecurityOrchestrationPolicies::PolicyRuleEvaluationService.new(merge_request)
      end

      def build_violation_data(vulnerabilities)
        return if vulnerabilities.blank?

        violated_uuids = vulnerabilities.with_findings
                                        .limit(Security::ScanResultPolicyViolation::MAX_VIOLATIONS)
                                        .map(&:finding_uuid)
        { uuids: { previously_existing: violated_uuids } }
      end
    end
  end
end
