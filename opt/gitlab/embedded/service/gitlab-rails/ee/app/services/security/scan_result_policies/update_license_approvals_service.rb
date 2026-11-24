# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class UpdateLicenseApprovalsService
      include Gitlab::Utils::StrongMemoize
      include ::Security::ScanResultPolicies::PolicyLogger
      include ::Security::ScanResultPolicies::RelatedPipelines

      def initialize(merge_request, pipeline, preexisting_states = false)
        @merge_request = merge_request
        @pipeline = pipeline
        @preexisting_states = preexisting_states
      end

      def execute
        return if merge_request.merged?

        approval_rules = merge_request
                           .approval_rules
                           .report_approver
                           .license_scanning
                           .including_scan_result_policy_read
                           .including_approval_policy_rule
        return if approval_rules.empty?

        if !preexisting_states && !scanner.results_available?
          log_update_approval_rule(no_results_message)
          return
        end

        filtered_rules = filter_approval_rules(approval_rules)
        return if filtered_rules.empty?

        evaluate_rules(filtered_rules)
        evaluation.save
      end

      private

      attr_reader :merge_request, :pipeline, :preexisting_states

      delegate :project, to: :merge_request

      def filter_approval_rules(approval_rules)
        rule_filter = ->(approval_rule) { approval_rule.approval_policy_source&.newly_detected? }

        preexisting_states ? approval_rules.reject(&rule_filter) : approval_rules.select(&rule_filter)
      end

      def evaluate_rules(license_approval_rules)
        log_update_approval_rule('Evaluating license_scanning rules from approval policies', **validation_context)
        license_approval_rules.each do |approval_rule|
          # We only error for fail-open. Fail closed policy is evaluated as "failing"
          if !target_branch_pipeline(approval_rule) && fail_open?(approval_rule)
            evaluation.error!(approval_rule, :target_pipeline_missing, context: validation_context(approval_rule))
            next
          end

          rule_violated, violation_data, denied_licenses = rule_violated?(approval_rule)

          if rule_violated
            evaluation.fail!(approval_rule, data: violation_data, context: validation_context(approval_rule))
            evaluation.add_violation_detail_data!(approval_rule,
              full_dependencies_by_license: denied_licenses.transform_values { |deps| Array.wrap(deps).map(&:to_s) })
            log_update_approval_rule('Updating MR approval rule', reason: 'license_finding rule violated',
              approval_rule_id: approval_rule.id, approval_rule_name: approval_rule.name, approval_rule: approval_rule)
          else
            evaluation.pass!(approval_rule)
          end
        end
      end

      def rule_violated?(rule)
        denied_licenses_with_dependencies = denied_licenses_with_dependency(rule)

        if denied_licenses_with_dependencies.present?
          return true, build_violation_data(denied_licenses_with_dependencies), denied_licenses_with_dependencies
        end

        [false, nil, nil]
      end

      def denied_licenses_with_dependency(rule)
        if licenses_with_package_exclusions?(rule)
          checker_class = if Feature.enabled?(:license_expression_checker, project)
                            Security::MergeRequestApprovalPolicies::LicenseExpressionChecker
                          else
                            Security::MergeRequestApprovalPolicies::DeniedLicensesChecker
                          end

          checker_class
            .new(project, report, target_branch_report(rule), rule.approval_policy_source)
            .denied_licenses_with_dependencies
        else
          Security::ScanResultPolicies::LicenseViolationChecker
            .new(project, report, target_branch_report(rule))
            .execute(rule.approval_policy_source)
        end
      end

      def licenses_with_package_exclusions?(rule)
        rule.approval_policy_source&.licenses.present?
      end

      def no_results_message
        if source_pipeline.present? && !source_pipeline.complete_or_manual?
          return 'Waiting for the pipeline to complete before evaluating SBOM reports'
        end

        'No SBOM reports found for the pipeline'
      end

      def scanner
        ::Gitlab::LicenseScanning.scanner_for_pipeline(project, source_pipeline,
          self_and_project_descendants: include_child_pipeline_sboms?)
      end
      strong_memoize_attr :scanner

      def report
        scanner.report
      end

      def target_branch_report(approval_rule)
        pipeline = target_branch_pipeline(approval_rule)
        # Matches `latest_comparison_pipeline_with_sbom_reports`, which counts SBOM reports in child pipelines.
        strong_memoize_with(:target_branch_report_by_pipeline, pipeline&.id) do
          ::Gitlab::LicenseScanning.scanner_for_pipeline(project, pipeline,
            self_and_project_descendants: include_child_pipeline_sboms?).report
        end
      end

      def include_child_pipeline_sboms?
        Feature.enabled?(:license_policy_child_pipeline_sboms, project)
      end
      strong_memoize_attr :include_child_pipeline_sboms?

      def evaluation
        @evaluation ||= Security::SecurityOrchestrationPolicies::PolicyRuleEvaluationService.new(merge_request)
      end

      def source_pipeline
        return pipeline if pipeline.nil?

        if include_child_pipeline_sboms?
          # Each pipeline in a hierarchy evaluates the same rules when it finishes,
          # so all of them read the whole hierarchy or the last one to finish wins.
          root_pipeline = pipeline.root_ancestor
          return root_pipeline if root_pipeline.has_self_or_descendant_reports?(::Ci::JobArtifact.of_report_type(:sbom))
        end

        return pipeline if pipeline.has_sbom_reports?

        # We use dependency_scanning_reports instead of SBOM reports because
        # container scanning job also generates SBOM reports. We might pick a pipeline with CS job and not DS job.
        # TODO: Investigate use of SBOM reports in https://gitlab.com/gitlab-org/gitlab/-/issues/500106
        pipeline_with_dependency_scanning_reports(related_pipelines(pipeline)) || pipeline
      end
      strong_memoize_attr :source_pipeline

      def target_branch_pipeline(approval_rule)
        strong_memoize_with(:target_branch_pipeline, approval_rule) do
          target_pipeline = target_pipeline_for_merge_request(merge_request, :license_scanning, approval_rule)

          target_pipeline || related_target_pipeline
        end
      end

      def related_target_pipeline
        target_pipeline_without_report = merge_request.merge_base_pipeline || merge_request.base_pipeline

        return unless target_pipeline_without_report

        related_pipeline_ids = Security::RelatedPipelinesFinder.new(target_pipeline_without_report, {
          sources: Enums::Ci::Pipeline.ci_and_security_orchestration_sources.values,
          ref: merge_request.target_branch
        }).execute

        pipeline_with_dependency_scanning_reports(project.all_pipelines.id_in(related_pipeline_ids))
      end

      def pipeline_with_dependency_scanning_reports(pipelines)
        pipelines.find { |pipeline| pipeline.self_and_project_descendants.any?(&:has_dependency_scanning_reports?) }
      end

      def validation_context(approval_rule = nil)
        if approval_rule
          { pipeline_ids: [source_pipeline&.id].compact,
            target_pipeline_ids: [target_branch_pipeline(approval_rule)&.id].compact }
        else
          { pipeline_ids: [source_pipeline&.id].compact }
        end
      end

      def log_update_approval_rule(message, **attributes)
        log_policy_evaluation('update_approvals', message,
          project: project, merge_request_id: merge_request.id,
          merge_request_iid: merge_request.iid, **attributes.merge(validation_context(attributes[:approval_rule])))
      end

      def build_violation_data(denied_licenses_with_dependencies)
        return if denied_licenses_with_dependencies.blank?

        denied_licenses_with_dependencies.first(Security::ScanResultPolicyViolation::MAX_VIOLATIONS)
                                         .to_h
                                         .transform_values do |dependencies|
          Security::ScanResultPolicyViolation.trim_violations(dependencies)
        end
      end

      def fail_open?(approval_rule)
        approval_rule.approval_policy_source&.fail_open?
      end
    end
  end
end
