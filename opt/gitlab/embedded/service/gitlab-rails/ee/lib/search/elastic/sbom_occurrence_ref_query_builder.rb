# frozen_string_literal: true

module Search
  module Elastic
    class SbomOccurrenceRefQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override

      DOC_TYPE = ::Search::Elastic::References::Sbom::OccurrenceRef::DOC_TYPE
      QUERY_COMPONENTS = {
        ::Search::Elastic::Filters => %i[
          by_traversal_ids
          by_archived
        ],
        ::Search::Elastic::SbomOccurrenceRefFilters => %i[
          by_project_ids
          by_component_ids
          by_component_names
          by_package_managers
          by_source_types
          by_component_versions
          by_licenses
          by_malware
          by_security_project_tracked_context_id
          by_tracked_refs_scope
        ],
        ::Search::Elastic::SbomOccurrenceRefAggregations => %i[
          by_component_and_version
          by_version_counts
        ],
        ::Search::Elastic::Formats => [
          { method: :source_fields, skip_if_size_zero: true },
          { method: :collapse, skip_if_size_zero: true }
        ],
        ::Search::Elastic::SbomOccurrenceRefSorts => [
          { method: :sort_by, skip_if_size_zero: true }
        ]
      }.freeze

      private

      override :base_options
      def base_options
        { source_fields: ::Search::Elastic::References::Sbom::OccurrenceRef::DEFAULT_SOURCE_FIELDS }
      end

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          traversal_ids_prefix: :traversal_ids
        }
      end
    end
  end
end
