# frozen_string_literal: true

module Security
  class UnenforceablePolicyRulesNotificationService
    include Gitlab::Utils::StrongMemoize
    include ::Security::ScanResultPolicies::RelatedPipelines
    include ::Security::ScanResultPolicies::VulnerabilityStatesHelper
    include ::Security::ScanResultPolicies::PolicyLogger

    def initialize(merge_request)
      @merge_request = merge_request
      @pipeline = merge_request.diff_head_pipeline
    end

    def execute
      # When a pipeline exists but hasn't completed yet, or when `CreatePipelineWorker`
      # is queued but hasn't executed yet, defer evaluation. The pipeline completion
      # path will re-evaluate reports post-completion.
      if (pipeline && !pipeline.complete_or_manual?) || merge_request.pipeline_creating?
        return log_message(nil, "Pipeline pending or in creation, deferring evaluation")
      end

      approval_rules = merge_request
        .approval_rules
        .including_scan_result_policy_read
        .including_approval_policy_rule

      update_for_report_type(merge_request, :scan_finding, approval_rules.scan_finding)
      update_for_report_type(merge_request, :license_scanning, approval_rules.license_scanning)
    end

    private

    attr_reader :merge_request, :pipeline

    delegate :project, to: :merge_request, private: true

    def update_for_report_type(merge_request, report_type, approval_rules)
      pipelines = pipelines_with_enforceable_reports(report_type)
      if pipelines.present?
        log_message(report_type, "No unenforceable #{report_type} rules detected, skipping",
          pipelines_with_reports_ids: pipelines.map(&:id))
        return
      end

      unblock_fail_open_rules(report_type)

      # We only evaluate newly detected states. Pre-existing states don't require pipeline to evaluate.
      # Pre-existing rules are evaluated by `Security::ScanResultPolicies::SyncPreexistingStatesApprovalRulesWorker`
      applicable_rules = filter_newly_detected_rules(report_type, approval_rules)
      return if applicable_rules.blank?

      log_message(report_type, "Unenforceable #{report_type} rules detected")
      policy_evaluation = Security::SecurityOrchestrationPolicies::PolicyRuleEvaluationService.new(merge_request)

      applicable_rules.each do |rule|
        policy_evaluation.error!(rule, pipeline_error, context: validation_context(report_type, rule))
      end

      policy_evaluation.save
    end

    def pipelines_with_enforceable_reports(report_type)
      return [] if pipeline.nil?

      pipelines = related_pipelines(pipeline)
      case report_type
      when :scan_finding
        # Pipelines which can store security reports are handled via SyncFindingsToApprovalRulesService
        pipelines.select(&:can_store_security_reports?)
      when :license_scanning
        # Pipelines which have scanning results available are handled via SyncLicenseScanningRulesService
        pipelines.select(&:can_ingest_sbom_reports?)
      end
    end

    def unblock_fail_open_rules(report_type)
      Security::ScanResultPolicies::UnblockFailOpenApprovalRulesService
        .new(merge_request: merge_request, report_types: [report_type])
        .execute
    end

    def pipeline_error
      pipeline&.failed? ? :pipeline_failed : :artifacts_missing
    end

    def validation_context(report_type, rule)
      return if pipeline.nil?

      { pipeline_ids: related_pipeline_ids(pipeline),
        target_pipeline_ids: related_target_pipeline_ids_for_merge_request(merge_request, report_type, rule) }
    end

    def log_message(report_type, message, **attributes)
      log_policy_evaluation('unenforceable_rules', message,
        project: project, report_type: report_type, merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid, related_pipeline_ids: related_pipeline_ids(pipeline), **attributes)
    end
  end
end
