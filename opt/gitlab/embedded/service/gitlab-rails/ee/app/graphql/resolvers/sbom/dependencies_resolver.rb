# frozen_string_literal: true

module Resolvers
  module Sbom
    class DependenciesResolver < DependencyInterfaceResolver
      include ::Sbom::OccurrenceRefsFilterable

      type Types::Sbom::DependencyType.connection_type, null: true

      private

      def dependencies(params)
        validate_advanced_filters!(params) if advanced_filters_supported?

        return advanced_dependencies(params) if use_elasticsearch?(params)

        result = ::Sbom::DependenciesFinder.new(object, params: mapped_params(params)).execute

        result = result.with_version if params[:component_versions].present? || params[:not_component_versions].present?

        apply_lookahead(result)
      end

      def use_elasticsearch?(filters)
        advanced_filters_supported? && super
      end

      # The advanced finder is project-scoped, but this resolver is also mounted on Group and
      # Vulnerability.
      def advanced_filters_supported?
        object.is_a?(::Project)
      end

      def filterable_namespace
        project_or_namespace
      end

      # `with_version` has no counterpart here: it only preloads :component_version, which
      # `preloads` already covers through lookahead.
      def advanced_dependencies(params)
        result = ::Search::AdvancedFinders::Sbom::DependenciesFinder
          .new(object, params: mapped_params(params, include_malware: true)).execute

        apply_lookahead(result)
      end

      # ElasticConnection keyset-paginates the relation itself; the offset wrapper is Postgres-only.
      def paginate(list)
        return list if list.is_a?(::Search::Elastic::Relation)

        super
      end

      def preloads
        super.merge(
          has_dependency_paths: :sbom_graph_paths_as_descendant,
          malware: [:project, :component, :component_version],
          tracked_refs_count: :occurrence_refs
        )
      end
    end
  end
end
