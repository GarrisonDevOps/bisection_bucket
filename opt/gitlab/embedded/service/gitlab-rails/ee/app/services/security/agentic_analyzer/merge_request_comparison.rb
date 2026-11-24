# frozen_string_literal: true

module Security
  module AgenticAnalyzer
    # Head and base pipelines of the MR security comparison of one report type, with the
    # agentic analyzer scans of the head SHA and of the target branch.
    # Built once per report type by MergeRequest#security_report_comparison.
    class MergeRequestComparison
      include Gitlab::Utils::StrongMemoize

      def initialize(merge_request, report_type)
        @merge_request = merge_request
        @report_type = report_type
      end

      # For the report types the agentic analyzer scan publishes (SAST), an MR without a
      # head pipeline is compared from the scan's workload pipeline at the head SHA.
      def head_pipeline
        return diff_head_pipeline if diff_head_pipeline || !agentic_security_comparison?

        agentic_head_pipeline
      end

      def base_pipeline
        return latest_scan_finding_comparison_pipeline unless agentic_security_comparison?

        # With only an agentic analyzer scan on the head (no head pipeline, or one that ran no
        # scan of this type), compare it against the agentic analyzer scan of the target branch
        # alone, so the findings of scanners that did not run on the head are not reported as fixed.
        return agentic_security_base_pipeline if agentic_security_head_pipeline_ids.any? && !diff_head_pipeline_scanned?

        # Without an agentic analyzer scan on the head, its base would report every
        # agentic analyzer finding on the target branch as fixed.
        return latest_scan_finding_comparison_pipeline if agentic_security_head_pipeline_ids.empty?

        latest_scan_finding_comparison_pipeline || agentic_security_base_pipeline
      end
      strong_memoize_attr :base_pipeline

      # Agentic analyzer scan pipelines (one head and base per analyzer) compared with the head and
      # base pipelines above, so all SAST findings show in one report. Finding UUIDs keep each
      # scanner's findings apart; empty lists are dropped.
      def additional_pipeline_ids
        return {} unless agentic_security_comparison? && agentic_security_head_pipeline_ids.any?

        {
          additional_head_pipeline_ids: agentic_security_head_pipeline_ids - [head_pipeline&.id],
          additional_base_pipeline_ids: agentic_security_base_pipelines.map(&:id) - [base_pipeline&.id]
        }.compact_blank
      end

      private

      attr_reader :merge_request, :report_type

      delegate :project, :diff_head_pipeline, :diff_head_sha, :target_branch,
        :latest_scan_finding_comparison_pipeline, to: :merge_request, private: true

      def agentic_security_comparison?
        ::Security::AgenticAnalyzer::AGENTIC_REPORT_TYPES.include?(report_type.to_s) &&
          ::Security::AgenticAnalyzer.enabled?(project)
      end

      def agentic_head_pipeline
        ::Security::AgenticAnalyzer.scan_pipeline_for(project, diff_head_sha, report_type.to_s)
      end
      strong_memoize_attr :agentic_head_pipeline

      def diff_head_pipeline_scanned?
        diff_head_pipeline.present? &&
          ::Security::AgenticAnalyzer.pipeline_has_successful_scan?(diff_head_pipeline, report_type)
      end
      strong_memoize_attr :diff_head_pipeline_scanned?

      def agentic_security_head_pipeline_ids
        ::Security::AgenticAnalyzer.scan_pipeline_ids_for(project, diff_head_sha)
      end
      strong_memoize_attr :agentic_security_head_pipeline_ids

      # One base pipeline per analyzer that also scanned the head, newest first, so an analyzer
      # missing from the head does not report its branch findings as fixed.
      def agentic_security_base_pipelines
        head_analyzers = ::Security::AgenticAnalyzer.workload_analyzers_at(project, diff_head_sha)
          .values_at(*agentic_security_head_pipeline_ids).compact.uniq
        ::Security::AgenticAnalyzer.latest_branch_scan_pipelines_for(project, target_branch, analyzers: head_analyzers)
      end
      strong_memoize_attr :agentic_security_base_pipelines

      def agentic_security_base_pipeline
        agentic_security_base_pipelines.first
      end
    end
  end
end
