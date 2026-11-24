# frozen_string_literal: true

# This concern provides shared CVE enrichment filtering logic
# for both Security::Finding and Vulnerabilities::Finding models.
module Security
  module CveEnrichmentFilterable
    extend ActiveSupport::Concern

    included do
      scope :with_cve_enrichment_filters, ->(
        known_exploited: nil, epss_operator: nil, epss_value: nil, include_findings_without_enrichment_data: nil
      ) do
        has_enrichment_filters = known_exploited == true || (epss_operator && epss_value)

        break none unless has_enrichment_filters

        enrichment_table = Security::FindingEnrichment.arel_table

        matched_enrichment_exists = Security::FindingEnrichment
          .where(enrichment_table[:finding_uuid].eq(arel_table[:uuid]))
          .with_enrichment_filters(
            known_exploited: known_exploited,
            epss_operator: epss_operator,
            epss_value: epss_value
          )
          .arel
          .exists

        if include_findings_without_enrichment_data == true
          any_usable_enrichment_exists = Security::FindingEnrichment
            .where(enrichment_table[:finding_uuid].eq(arel_table[:uuid]))
            .where.not(cve_enrichment_id: nil)
            .arel
            .exists

          where(matched_enrichment_exists.or(any_usable_enrichment_exists.not))
        else
          where(matched_enrichment_exists)
        end
      end
    end
  end
end
