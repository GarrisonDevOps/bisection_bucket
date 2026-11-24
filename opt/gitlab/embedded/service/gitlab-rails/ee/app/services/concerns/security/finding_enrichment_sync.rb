# frozen_string_literal: true

module Security
  module FindingEnrichmentSync
    def upsert_finding_enrichments(findings, error_context)
      cve_names = extract_unique_cve_names(findings)
      return if cve_names.empty?

      enrichments_by_cve = load_enrichments_by_cve(cve_names)
      records = build_finding_enrichments(findings, enrichments_by_cve)

      Security::FindingEnrichment.upsert_all(
        records,
        unique_by: %i[finding_uuid cve],
        on_duplicate: on_duplicate_sql
      )
    rescue StandardError => exception
      Gitlab::ErrorTracking.track_exception(exception, **error_context, class: self.class.name)
    end

    private

    def extract_unique_cve_names(findings)
      findings
        .flat_map { |f| cve_identifiers_for(f) }
        .filter_map(&:name)
        .uniq
    end

    def load_enrichments_by_cve(cve_names)
      PackageMetadata::CveEnrichment
        .by_cves(cve_names)
        .index_by(&:cve)
    end

    def build_finding_enrichments(findings, enrichments_by_cve)
      findings.flat_map do |finding|
        cve_identifiers = cve_identifiers_for(finding)
        next [] if cve_identifiers.empty?

        cve_identifiers.map do |identifier|
          enrichment = enrichments_by_cve[identifier.name]

          {
            project_id: project.id,
            finding_uuid: finding.uuid,
            cve_enrichment_id: enrichment&.id,
            cve: identifier.name,
            epss_score: enrichment&.epss_score,
            is_known_exploit: enrichment&.is_known_exploit,
            vulnerability_id: vulnerability_id_for(finding),
            updated_at: current_timestamp
          }
        end
      end
    end

    def vulnerability_id_for(finding)
      finding.vulnerability_id if finding.is_a?(Vulnerabilities::Finding)
    end

    def on_duplicate_sql
      Arel.sql(<<~SQL.squish)
        cve_enrichment_id = EXCLUDED.cve_enrichment_id,
        epss_score = EXCLUDED.epss_score,
        is_known_exploit = EXCLUDED.is_known_exploit,
        vulnerability_id = COALESCE(security_finding_enrichments.vulnerability_id, EXCLUDED.vulnerability_id),
        updated_at = EXCLUDED.updated_at
      SQL
    end

    def current_timestamp
      @current_timestamp ||= Time.current
    end
  end
end
