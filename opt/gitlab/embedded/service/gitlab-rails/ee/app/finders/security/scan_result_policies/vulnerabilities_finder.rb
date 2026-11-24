# frozen_string_literal: true

# This finder is used to filter the vulnerabilities for default branch that matches the
# conditions specified in scan result policy rules.
module Security
  module ScanResultPolicies
    class VulnerabilitiesFinder
      include CveEnrichmentFilters

      INTERVAL_IN_DAYS = {
        day: 1,
        week: 7,
        month: 30,
        year: 365
      }.freeze

      def initialize(project, params = {})
        @project = project
        @params = params
      end

      attr_reader :project, :params

      def execute
        vulnerabilities = project.vulnerabilities.for_default_branch

        vulnerabilities = vulnerabilities.with_limit(params[:limit]) if params[:limit].present?
        vulnerabilities = vulnerabilities.with_states(params[:state]) if params[:state].present?
        vulnerabilities = vulnerabilities.with_severities(params[:severity]) if params[:severity].present?
        vulnerabilities = vulnerabilities.with_report_types(params[:report_type]) if params[:report_type].present?
        vulnerabilities = vulnerabilities.by_age(vulnerability_age[:operator], age_in_days) if vulnerability_age_valid?
        vulnerabilities = vulnerabilities.with_fix_available(params[:fix_available]) unless params[:fix_available].nil?
        vulnerabilities = vulnerabilities.with_findings_by_uuid(params[:uuids]) if params[:uuids].present?
        vulnerabilities = apply_cve_enrichment_filters(vulnerabilities) if valid_cve_enrichment_params?

        unless params[:false_positive].nil?
          vulnerabilities = vulnerabilities.with_false_positive(params[:false_positive])
        end

        vulnerabilities
      end

      private

      def vulnerability_age
        params[:vulnerability_age]
      end

      def vulnerability_age_valid?
        vulnerability_age.present? &&
          vulnerability_age[:operator].in?(%i[greater_than less_than]) &&
          vulnerability_age[:interval].in?(%i[day week month year]) &&
          vulnerability_age[:value].is_a?(::Integer)
      end

      def age_in_days
        vulnerability_age[:value] * INTERVAL_IN_DAYS[vulnerability_age[:interval]]
      end
    end
  end
end
