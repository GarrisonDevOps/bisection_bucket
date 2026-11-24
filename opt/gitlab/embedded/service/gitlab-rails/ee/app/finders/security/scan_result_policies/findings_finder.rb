# frozen_string_literal: true

# Security::ScanResultPolicies::FindingsFinder
#
# This finder returns `Security::Finding` for a given pipeline
# and a list of given pipeline ids with conditions matching the rules
# configured in scan result policies.
#
# Arguments:
#   pipeline - pipeline for which the findings should be returned
#   params:
#     scanners:             Array<String>
#     severity_levels:      Array<String>
#     related_pipeline_ids: Array<Integer>
#     false_positive:       Boolean
#     fix_available:        Boolean
#     known_exploited:      Boolean
#     epss_score:           Float
#     enrichment_data_unavailable_action: String
#     dismissed:            Boolean/nil - true: only dismissed, false: exclude dismissed, nil: no filter
#     malicious:            Boolean - when true returns only findings whose identifiers
#                           carry a malware prefix (GLAM- / MAL-) on the requested scanners.
module Security
  module ScanResultPolicies
    class FindingsFinder
      include CveEnrichmentFilters

      def initialize(project, pipeline, params = {})
        @project = project
        @pipeline = pipeline
        @params = params
      end

      attr_reader :project, :pipeline, :params

      def execute
        findings = security_findings

        findings = findings.by_severity_levels(params[:severity_levels]) if params[:severity_levels].present?
        findings = findings.by_report_types(params[:scanners]) if params[:scanners].present?
        findings = findings.malicious if params[:malicious]
        findings = findings.undismissed_by_vulnerability if params[:dismissed] == false
        findings = findings.by_state(:dismissed) if params[:dismissed] == true
        findings = findings.false_positives if params[:false_positive] == true
        findings = findings.non_false_positives if params[:false_positive] == false
        findings = findings.fix_available if params[:fix_available] == true
        findings = findings.no_fix_available if params[:fix_available] == false
        findings = findings.with_scan_partition_number.by_uuid(params[:uuids]) if params[:uuids].present?
        findings = apply_cve_enrichment_filters(findings) if valid_cve_enrichment_params?

        findings
      end

      private

      def security_findings
        return Security::Finding.none unless pipeline

        findings = if params[:related_pipeline_ids].present?
                     Security::Finding.by_project_id_and_pipeline_ids(project.id, params[:related_pipeline_ids])
                   else
                     pipeline.security_findings.by_partition_number(pipeline.security_findings_partition_number)
                   end

        findings.merge(::Security::Scan.latest_successful)
      end
    end
  end
end
