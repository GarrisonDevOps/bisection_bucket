# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class IngestFindingRiskScores < AbstractTask
        include Gitlab::Ingestion::BulkInsertableTask

        self.model = Vulnerabilities::FindingRiskScore
        self.unique_by = :finding_id

        private

        def attributes
          findings.map do |finding|
            {
              project_id: finding[:project_id],
              finding_id: finding[:id],
              risk_score: Vulnerabilities::RiskScore.new(
                severity: finding[:severity],
                epss_score: finding[:epss_score],
                is_known_exploit: finding[:is_known_exploit]).score
            }
          end
        end

        def findings
          cve_by_finding, enrichments_by_cve = preload_cve_enrichments

          finding_maps.map do |finding_map|
            cve = cve_by_finding[finding_map.finding_id]
            enrichment = enrichments_by_cve[cve]
            {
              id: finding_map.finding_id,
              project_id: finding_map.project.id,
              severity: finding_map.severity,
              epss_score: enrichment&.epss_score || 0.0,
              is_known_exploit: enrichment&.is_known_exploit || false
            }
          end
        end

        def preload_cve_enrichments
          cve_by_finding = extract_cve_values(finding_maps)
          enrichments_by_cve = extract_cve_enrichments(cve_by_finding.values)

          [cve_by_finding, enrichments_by_cve]
        end

        def extract_cve_values(finding_maps)
          finding_maps.index_by(&:finding_id)
            .transform_values { |finding_map| finding_map.report_finding.identifiers.find(&:cve?)&.external_id }
        end

        def extract_cve_enrichments(cve_values)
          unique_cves = cve_values.uniq
          return {} if unique_cves.empty?

          cve_enrichments = ::PackageMetadata::CveEnrichment.by_cves(unique_cves)
          cve_enrichments.index_by(&:cve)
        end
      end
    end
  end
end
