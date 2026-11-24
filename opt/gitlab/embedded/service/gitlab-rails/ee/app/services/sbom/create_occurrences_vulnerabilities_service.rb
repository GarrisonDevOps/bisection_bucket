# frozen_string_literal: true

module Sbom
  class CreateOccurrencesVulnerabilitiesService
    def self.execute(finding_data)
      new(finding_data).execute
    end

    def initialize(finding_data)
      @finding_data = finding_data
    end

    def execute
      return unless filtered_data.present?

      result = fetch_occurrence_data
      return if result.cmd_tuples == 0

      attributes, vuln_ids = build_attributes_and_vulnerability_ids(result)

      Sbom::OccurrencesVulnerability.insert_all(
        attributes,
        unique_by: [:sbom_occurrence_id, :vulnerability_id, :project_id]
      )

      ::Vulnerabilities::EsHelper.sync_elasticsearch(vuln_ids)
    end

    private

    attr_reader :finding_data

    # rubocop:disable CodeReuse/ActiveRecord -- Custom query
    def fetch_occurrence_data
      cte_sql = "WITH cte (uuid, purl_type, component_name, version, project_id, vulnerability_id) AS (#{cte_values})"
      select_sql = Sbom::Occurrence
        .joins('INNER JOIN cte ON cte.project_id = sbom_occurrences.project_id')
        .joins('INNER JOIN sbom_components
          ON sbom_components.id = sbom_occurrences.component_id
          AND sbom_components.name = cte.component_name
          AND cte.purl_type = sbom_components.purl_type')
        .joins('INNER JOIN sbom_component_versions
          ON sbom_component_versions.id = sbom_occurrences.component_version_id
          AND cte.version = sbom_component_versions.version')
        .joins('INNER JOIN vulnerabilities ON cte.vulnerability_id = vulnerabilities.id')
        .select('cte.uuid', 'cte.project_id', 'sbom_occurrences.id', 'vulnerabilities.finding_id').to_sql

      full_query = [cte_sql, select_sql].join("\n")

      Sbom::Occurrence.connection.execute(full_query)
    end
    # rubocop:enable CodeReuse/ActiveRecord

    def cte_values
      Arel::Nodes::ValuesList.new(filtered_data).to_sql
    end

    def filtered_data
      @filtered_data ||= finding_data.map do |data|
        data[:purl_type] = ::Enums::Sbom.purl_types[data[:purl_type]]
        data.values_at(:uuid, :purl_type, :package_name, :package_version, :project_id, :vulnerability_id)
      end
    end

    def vulnerability_ids
      @vulnerability_ids ||= finding_data.to_h { |data| [data[:uuid], data[:vulnerability_id]] }
    end

    def build_attributes_and_vulnerability_ids(result)
      vuln_ids = []

      attributes = result.map do |data|
        vulnerability_id = vulnerability_ids[data['uuid']]
        vuln_ids << vulnerability_id

        build_occurrence_vulnerability_attributes(data, vulnerability_id)
      end

      [attributes, vuln_ids.uniq.compact]
    end

    def build_occurrence_vulnerability_attributes(data, vulnerability_id)
      {
        sbom_occurrence_id: data['id'],
        vulnerability_id: vulnerability_id,
        project_id: data['project_id'],
        vulnerability_occurrence_id: data['finding_id']
      }
    end
  end
end
