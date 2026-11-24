# frozen_string_literal: true

module Resolvers
  module Sbom
    class DependencyVulnerabilitiesResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::VulnerabilityType.connection_type, null: true

      authorize :read_dependency
      authorizes_object!

      def resolve(**_args)
        return [] unless object

        BatchLoader::GraphQL.for(object.id).batch do |ids, loader|
          occurrence_vulnerabilities = ::Sbom::OccurrencesVulnerability
            .for_occurrence_ids(ids)
            .ordered_by_vulnerability
          by_occurrence = occurrence_vulnerabilities.group_by(&:sbom_occurrence_id)

          vulnerability_ids = occurrence_vulnerabilities.map(&:vulnerability_id)
          vulnerabilities = Vulnerability.id_in(vulnerability_ids).with_findings.index_by(&:id)

          ids.each do |id|
            results = by_occurrence[id]&.filter_map { |r| vulnerabilities[r.vulnerability_id] } || []
            loader.call(id, results)
          end
        end
      end
    end
  end
end
