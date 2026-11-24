# frozen_string_literal: true

module Ci
  class SyncReportsToApprovalRulesService < ::BaseService
    def initialize(pipeline)
      @pipeline = pipeline
    end

    def execute
      sync_license_scanning_rules
      sync_coverage_rules
      success
    rescue StandardError => error
      payload = {
        pipeline: pipeline&.to_param,
        source: "#{__FILE__}:#{__LINE__}"
      }

      Gitlab::ExceptionLogFormatter.format!(error, payload)
      log_error(payload)
      error("Failed to update approval rules")
    end

    private

    attr_reader :pipeline

    def sync_license_scanning_rules
      ::Security::SyncLicenseScanningRulesService.execute(pipeline)
    end

    def sync_coverage_rules
      return unless pipeline.complete?

      pipeline.update_builds_coverage
      return unless pipeline.coverage.present?

      remove_required_approvals_for(ApprovalMergeRequestRule.code_coverage, merge_requests_approved_coverage)
    end

    def merge_requests_approved_coverage
      pipeline.merge_requests_as_head_pipeline.reject do |merge_request|
        require_coverage_approval?(merge_request)
      end
    end

    def require_coverage_approval?(merge_request)
      threshold = if Feature.enabled?(:coverage_minimum_threshold, merge_request.target_project)
                    coverage_minimum_threshold_for(merge_request)
                  end

      ::Gitlab::Ci::CoverageApprovalCheck.check(
        merge_request: merge_request,
        pipeline: pipeline,
        threshold: threshold
      ).required?
    end

    def coverage_minimum_threshold_for(merge_request)
      merge_request.approval_rules.code_coverage.pick(:coverage_minimum_threshold)
    end

    def remove_required_approvals_for(rules, merge_requests)
      rules
        .for_unmerged_merge_requests(merge_requests)
        .update_all(approvals_required: 0)
    end
  end
end
