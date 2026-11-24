# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PolicyRuleEvaluationService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::InternalEventsTracking
      include ::Security::ScanResultPolicies::PolicyViolationCommentGenerator
      include ::Security::ScanResultPolicies::VulnerabilityStatesHelper

      def initialize(merge_request)
        @merge_request = merge_request
        @passed_rules = Set.new
        @failed_rules = Set.new
      end

      def save
        merge_request.reset_required_approvals(failed_rules) if failed_rules.any?
        ApprovalMergeRequestRule.remove_required_approved(passed_rules) if passed_rules.any?

        violations.execute
        log_policy_evaluation('evaluation_saved', 'Saved approval policy evaluation',
          Labkit::Fields::GL_PROJECT_PATH => project.full_path,
          merge_request_id: merge_request.id, merge_request_iid: merge_request.iid,
          passed_approval_rule_ids: passed_rules.map(&:id), failed_approval_rule_ids: failed_rules.map(&:id))
        generate_policy_bot_comment(merge_request)
      end

      def pass!(approval_rule)
        passed_rules.add(approval_rule)
        policy_source = approval_rule.approval_policy_source
        return unless policy_source

        violations.remove_violation(policy_source)
      end

      def fail!(approval_rule, data: nil, context: nil)
        failed_rules.add(approval_rule)
        policy_source = approval_rule.approval_policy_source
        return unless policy_source

        violations.add_violation(policy_source, approval_rule.report_type, data, context: context)
      end

      def add_violation_detail_data!(approval_rule, metadata)
        policy_source = approval_rule.approval_policy_source
        return unless policy_source

        violations.add_violation_detail_data(policy_source, metadata)
      end

      def error!(approval_rule, error, **extra_data)
        if excluded?(approval_rule)
          pass!(approval_rule)
          return
        end

        process_default_behaviour(approval_rule)

        policy_source = approval_rule.approval_policy_source
        return unless policy_source

        violations.add_error(policy_source, error, **extra_data)
      end

      def skip!(approval_rule)
        process_default_behaviour(approval_rule)
        policy_source = approval_rule.approval_policy_source
        violations.skip(policy_source) if policy_source
      end

      private

      attr_reader :merge_request, :passed_rules, :failed_rules

      delegate :project, to: :merge_request

      def excluded?(rule)
        return true unless rule_applies_to_target_branch?(rule)
        return false unless rule.approval_policy_source&.unblock_rules_using_execution_policies?
        return false unless rule_excludable?(rule)

        if execution_policy_scan_enforced?(rule)
          track_unblock_event(rule)
          return true
        end

        false
      end

      def rule_applies_to_target_branch?(rule)
        rule.applicable_to_branch?(merge_request.target_branch)
      end

      def process_default_behaviour(rule)
        if rule.approval_policy_source&.fail_open?
          passed_rules.add(rule)
        else
          failed_rules.add(rule)
        end
      end

      def violations
        @violations ||= Security::SecurityOrchestrationPolicies::UpdateViolationsService.new(merge_request)
      end

      def track_unblock_event(rule)
        track_internal_event(
          'unblock_approval_rule_using_scan_execution_policy',
          project: project,
          additional_properties: {
            label: extract_scanners(rule)&.join(',')
          }
        )
      end

      # Refactor the methods below with PORO classes: https://gitlab.com/gitlab-org/gitlab/-/issues/504305
      def execution_policy_scan_enforced?(rule)
        scanners = extract_scanners(rule)
        return false if scanners.blank?
        return false if unsuccessful_scan_job_exists?(scanners)

        enforced_scans = Set.new(active_scan_execution_policy_scans + pipeline_execution_policy_scans(rule))
        scanners.all? { |scanner| enforced_scans.include?(scanner) }
      end

      def pipeline_execution_policy_scans(rule)
        # NOTE: Only take configurations for the rule's configuration and its ancestors,
        # so that an approval rule defined by group cannot get unblocked by a project-level policy.
        configuration_ids = rule.security_orchestration_policy_configuration&.self_and_ancestor_configuration_ids
        return [] if configuration_ids.blank?

        project.security_policies.type_pipeline_execution_policy
               .for_policy_configuration(configuration_ids)
               .flat_map(&:enforced_scans).compact.uniq
      end

      # Only allow rules to be excludable if they only target newly detected states. We cannot reliably exclude
      # previously detected states based on active SEP, as they may not had been enforced on the target branch.
      def rule_excludable?(rule)
        case rule.report_type
        when 'scan_finding'
          only_newly_detected?(rule)
        when 'license_scanning'
          rule.approval_policy_source&.only_newly_detected_licenses? || false
        else
          false
        end
      end

      def extract_scanners(rule)
        case rule.report_type
        when 'scan_finding'
          scanners_from_rule(rule)
        when 'license_scanning'
          %w[dependency_scanning]
        end
      end

      def scanners_from_rule(rule)
        rule.scanners_from_configurations.presence ||
          rule.scanners.presence ||
          Security::ScanExecutionPolicy::PIPELINE_SCAN_TYPES
      end

      # Prevent bypass of approvals by canceling the scan jobs
      def unsuccessful_scan_job_exists?(scanners)
        pipeline = merge_request.diff_head_pipeline
        return false unless pipeline

        pipeline.builds
          .latest
          .with_secure_reports_from_config_options(scanners)
          .without_status(:success)
          .exists?
      end

      def active_scan_execution_policy_scans
        active_scans_for_ref = project.all_security_orchestration_policy_configurations
        .flat_map do |configuration|
          configuration.active_pipeline_policies_for_project(merge_request.source_branch_ref, project)
                       .flat_map { |policy| policy[:actions] }
        end
        # rubocop:disable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord -- used on hashes
        active_scans_for_ref.pluck(:scan)
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord
      end
      strong_memoize_attr :active_scan_execution_policy_scans
    end
  end
end
