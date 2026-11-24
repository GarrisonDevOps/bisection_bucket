# frozen_string_literal: true

# This module provides shared CVE enrichment filtering logic
# for both Security::ScanResultPolicies::FindingsFinder and Security::ScanResultPolicies::VulnerabilitiesFinder.
module Security
  module ScanResultPolicies
    module CveEnrichmentFilters
      private

      def apply_cve_enrichment_filters(records)
        records.with_cve_enrichment_filters(
          known_exploited: params[:known_exploited],
          epss_operator: params.dig(:epss_score, :operator),
          epss_value: params.dig(:epss_score, :value),
          include_findings_without_enrichment_data: include_findings_without_enrichment_data?
        )
      end

      def valid_cve_enrichment_params?
        params[:known_exploited] == true ||
          ::Security::ScanResultPolicy.epss_score_valid?(params[:epss_score])
      end

      def include_findings_without_enrichment_data?
        params[:enrichment_data_unavailable_action] == 'block'
      end
    end
  end
end
