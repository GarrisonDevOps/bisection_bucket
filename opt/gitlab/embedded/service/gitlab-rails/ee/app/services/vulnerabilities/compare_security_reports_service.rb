# frozen_string_literal: true

module Vulnerabilities
  class CompareSecurityReportsService < ::Ci::CompareReportsBaseService
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Loggable

    def build_comparer(base_report, head_report)
      comparison_params = params.merge(
        base_report: base_report,
        head_report: head_report,
        partial_scan_scanner_ids: partial_scan_scanner_ids,
        lean_findings: true
      )
      comparer_class.new(project, comparison_params)
    end

    # For full scan comparisons where the head pipeline includes partial scans,
    # identify the scanners configured for partial scanning and filter out their
    # findings from the base pipeline. This prevents vulnerabilities detected by
    # those scanners in the base pipeline from incorrectly appearing as "fixed"
    # in the full scan tab, since they're already handled in the partial scan comparison.
    def partial_scan_scanner_ids
      return [] unless params[:scan_mode] == 'full'
      return [] if head_pipeline.nil?

      external_ids = head_partial_scanner_external_ids | additional_head_partial_scanner_ids
      # A full scan at the same commit covers the scanner, so its fixed findings still show.
      external_ids -= head_full_scanner_external_ids if additional_head_pipeline_ids.any? && external_ids.any?

      return [] if external_ids.empty?

      # Lean findings only carry `scanner_id`, so resolve the external ids to the project's scanner records.
      project.vulnerability_scanners.with_external_id(external_ids).ids # rubocop:disable CodeReuse/ActiveRecord -- Bounded by scanners in a pipeline
    end

    def comparer_class
      Gitlab::Ci::Reports::Security::SecurityFindingsReportsComparer
    end

    def serializer_class
      Vulnerabilities::FindingDiffSerializer
    end

    def get_report(pipeline)
      return :parsing unless security_findings_stored?(pipeline)

      related_pipeline_ids = related_pipeline_ids_for(pipeline)
      limit = max_findings_count

      findings = Security::FindingsFinder.new(
        pipeline,
        params: {
          report_type: params[:report_type],
          scope: 'all',
          scan_mode: scan_mode_for_pipeline(pipeline),
          limit: limit,
          related_pipeline_ids: related_pipeline_ids,
          lean: true
        }
      ).execute

      findings_array = findings.to_a
      log_truncated_comparison(pipeline, findings_array, limit)
      findings_array = findings_array.uniq(&:uuid) if related_pipeline_ids.present?

      Gitlab::Ci::Reports::Security::AggregatedFinding.new(pipeline, findings_array)
    end

    def execute(base_pipeline, head_pipeline)
      @base_pipeline = base_pipeline
      @head_pipeline = head_pipeline
      super
    end

    private

    attr_reader :base_pipeline, :head_pipeline

    def max_findings_count
      if Feature.enabled?(:security_mr_reports_larger_comparison_set, project, type: :gitlab_com_derisk)
        Gitlab::Ci::Reports::Security::SecurityFindingsReportsComparer::LARGER_MAX_COMPARED_FINDINGS
      else
        Gitlab::Ci::Reports::Security::SecurityFindingsReportsComparer::MAX_COMPARED_FINDINGS
      end
    end

    # The finder loads up to `limit + 1` findings per scan and severity, so a larger group
    # means the comparison only saw part of that scan's findings.
    def log_truncated_comparison(pipeline, findings, limit)
      truncated = findings.map { |finding| [finding.scan_id, finding.severity] }.tally
        .select { |_, count| count > limit }
      return if truncated.empty?

      Gitlab::AppJsonLogger.info(
        build_structured_payload_labkit(
          Labkit::Fields::LOG_MESSAGE => 'Security report comparison truncated',
          Labkit::Fields::GL_PROJECT_ID => project.id,
          Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
          pipeline_role: pipeline == head_pipeline ? 'head' : 'base',
          report_type: params[:report_type],
          scan_mode: scan_mode_for_pipeline(pipeline),
          limit: limit,
          truncated_scans: truncated.keys.map { |scan_id, severity| { scan_id: scan_id, severity: severity } }
        )
      )
    end

    def scan_mode_for_pipeline(pipeline)
      # For partial scan comparisons, we want to compare full scan results from the base pipeline
      # against partial scan results from the head pipeline. This prevents existing vulnerabilities
      # from appearing as "new" when they're detected by partial scans on feature branches.
      if params[:scan_mode] == 'partial' && pipeline == base_pipeline
        'full'
      else
        params[:scan_mode]
      end
    end

    def security_findings_stored?(pipeline)
      return true if pipeline.nil?
      return false unless Security::Scan.results_ready?(pipeline, params[:report_type])
      return false if awaiting_scan_ingestion?(pipeline)

      !related_scans_processing?(pipeline)
    end

    # `results_ready?` is true before ingestion creates scans, so reports compare as zero findings. Checked per
    # pipeline, as each is ingested separately. Bounded like policy evaluation: an unlicensed report type, or a
    # CycloneDX SBOM without a dependency scanning source, never gets a scan and waits out the window.
    def awaiting_scan_ingestion?(pipeline)
      return false unless within_ingestion_wait?(pipeline)

      pipeline_ids_with_reports = pipeline.builds_in_self_and_project_descendants
        .with_existing_job_artifacts(::Ci::JobArtifact.security_reports)
        .distinct.pluck(:commit_id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- Bounded by the pipeline hierarchy size limit
      return false if pipeline_ids_with_reports.empty?

      ingested_pipeline_ids = Security::Scan.by_pipeline_ids(pipeline_ids_with_reports).latest
        .distinct.pluck(:pipeline_id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- Bounded by the pipeline hierarchy size limit

      (pipeline_ids_with_reports - ingested_pipeline_ids).any?
    end

    def within_ingestion_wait?(pipeline)
      # Pipelines blocked on manual jobs have no finished_at; updated_at approximates when they became manual.
      completed_at = pipeline.manual? ? pipeline.updated_at : pipeline.finished_at

      completed_at.present? &&
        completed_at >= ::Security::ScanResultPolicies::UnblockPendingMergeRequestViolationsWorker::MAX_INGESTION_WAIT.ago
    end

    def related_scans_processing?(pipeline)
      pipeline_ids = related_pipeline_ids_for(pipeline)
      return false if pipeline_ids.empty?

      Security::Scan
        .by_pipeline_ids(pipeline_ids)
        .by_scan_types(params[:report_type])
        .latest
        .processing
        .exists?
    end

    # Merge request approval policies and the security policy pipeline merge
    # check evaluate the latest pipelines of all sources for the head sha
    # (for example, both the branch pipeline and the merge request pipeline),
    # so the head report has to aggregate findings across the same set of
    # pipelines to match what those enforcement mechanisms report.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/599102.
    #
    # The caller can also pass additional head and base pipelines, such as the business
    # logic security scan's workload pipelines (see
    # MergeRequest#security_comparison_additional_pipeline_ids).
    def related_pipeline_ids_for(pipeline)
      return [] unless pipeline
      # Only ever called with the head or the base pipeline.
      return additional_base_pipeline_ids unless pipeline == head_pipeline

      related_pipeline_ids(pipeline) | additional_head_pipeline_ids
    end

    def additional_head_pipeline_ids
      Array(params[:additional_head_pipeline_ids])
    end

    def additional_base_pipeline_ids
      Array(params[:additional_base_pipeline_ids])
    end

    def head_partial_scanner_external_ids
      partial_scans = head_pipeline.security_scans.partial.to_a
      return [] if partial_scans.empty?

      build_type_pairs = partial_scans.map do |scan|
        file_type_value = ::Ci::JobArtifact.file_types[scan.scan_type]
        [scan.build_id, file_type_value]
      end

      artifacts = head_pipeline.job_artifacts
                               .security_reports_by_build_and_type_pairs(build_type_pairs)

      artifacts.filter_map do |artifact|
        artifact.security_report&.scanner&.external_id
      end.uniq
    end

    def additional_head_partial_scanner_ids
      return [] if additional_head_pipeline_ids.empty?

      Security::Scan.by_pipeline_ids(additional_head_pipeline_ids).by_scan_types(params[:report_type])
        .latest.partial.filter_map(&:report_scanner_external_id).uniq
    end

    def head_full_scanner_external_ids
      Security::Scan.by_pipeline_ids([head_pipeline.id] + additional_head_pipeline_ids)
        .by_scan_types(params[:report_type]).latest.succeeded.without_partial_scan
        .filter_map(&:report_scanner_external_id).uniq
    end

    def related_pipeline_ids(pipeline)
      @related_pipeline_ids ||= {}
      @related_pipeline_ids[pipeline.id] ||=
        Security::RelatedPipelinesFinder.cached_ci_and_security_orchestration_pipeline_ids(pipeline)
    end

    # The cache key has to change when a new related pipeline completes for
    # the head sha, so cached comparisons are invalidated once, for example,
    # a branch pipeline for the same commit finishes after the merge request
    # pipeline.
    override :key
    def key(base_pipeline, head_pipeline)
      comparison_key = super
      comparison_key += [related_pipeline_ids(head_pipeline).sort] if head_pipeline
      return comparison_key if additional_head_pipeline_ids.empty? && additional_base_pipeline_ids.empty?

      comparison_key + [additional_head_pipeline_ids.sort, additional_base_pipeline_ids.sort]
    end
  end
end
