# frozen_string_literal: true

# Elasticsearch-backed counterpart of ::Sbom::DependenciesFinder.
#
# Arguments:
#   project: the Project whose dependencies are listed.
#   params: optional! a hash with one or more of:
#     sort_by: name, packager, severity or license (the underlying column names also work)
#     sort: asc or desc
#     component_ids, component_names, component_versions, not: { component_versions: [] }
#     licenses, package_managers, source_types, malware
#     security_project_tracked_context_id, tracked_refs_scope
module Search
  module AdvancedFinders
    module Sbom
      class DependenciesFinder
        # `policy_violations` is absent and cannot be supported here: ::Sbom::DependenciesFinder
        # resolves it through Security::PolicyDismissal uuids, which are not indexed. Callers passing
        # it must keep using the PostgreSQL finder, otherwise they would get an unfiltered list.
        FORWARDED_PARAMS = %i[
          component_ids
          component_names
          component_versions
          licenses
          malware
          package_managers
          security_project_tracked_context_id
        ].freeze

        NIL_SOURCE = 'nil_source'
        UNKNOWN_SOURCE_TYPE = -1

        def initialize(project, params: {})
          @project = project
          @params = params
        end

        def execute
          query = ::Search::Elastic::SbomOccurrenceRefQueryBuilder.build(query: nil, options: search_params)

          ::Search::Elastic::Relation.new(::Sbom::Occurrence, query, es_search_options)
        end

        private

        attr_reader :project, :params

        def es_search_options
          {
            index_name: ::Search::Elastic::References::Sbom::OccurrenceRef.index,
            root_ancestor_ids: [project.root_ancestor.id],
            primary_key: :sbom_occurrence_id
          }
        end

        def search_params
          filter_params.merge(
            search_level: 'project',
            project_ids: [project.id],
            # ::Sbom::DependenciesFinder matches licenses[0..1].
            include_secondary_license: true,
            # The index holds one document per (occurrence, tracked ref), so selecting several refs
            # would otherwise return the same occurrence once per ref and shorten the page.
            collapse_field: :sbom_occurrence_id,
            sort_by: params[:sort_by],
            sort: params[:sort]
          )
        end

        def filter_params
          params.slice(*FORWARDED_PARAMS).to_h.symbolize_keys.merge(
            not_component_versions: params.dig(:not, :component_versions),
            source_types: source_types,
            tracked_refs_scope: params[:tracked_refs_scope]&.to_sym
          )
        end

        # The index holds the enum integer, and an occurrence with no source has no value at all, so
        # `nil_source` has to survive as a nil rather than as an unresolved name.
        def source_types
          requested = params[:source_types]
          return if requested.blank?

          values = Array.wrap(requested)
          known = values.filter_map { |type| ::Sbom::Source.source_types[type.to_s] }.uniq
          known << nil if values.any? { |type| type.nil? || type.to_s == NIL_SOURCE }

          known.presence || [UNKNOWN_SOURCE_TYPE]
        end
      end
    end
  end
end
