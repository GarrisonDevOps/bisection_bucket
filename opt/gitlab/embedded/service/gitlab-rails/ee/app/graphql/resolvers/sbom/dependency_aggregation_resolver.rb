# frozen_string_literal: true

module Resolvers
  module Sbom
    class DependencyAggregationResolver < DependencyInterfaceResolver
      type Types::Sbom::DependencyAggregationType.connection_type, null: true

      authorize :read_dependency
      authorizes_object!

      argument :project_count_min, GraphQL::Types::Int,
        required: false,
        description: 'Filter dependencies by minimum project count.'

      argument :project_count_max, GraphQL::Types::Int,
        required: false,
        description: 'Filter dependencies by maximum project count.'

      argument :project_ids, [::Types::GlobalIDType[::Project]],
        required: false,
        experiment: { milestone: '19.2' },
        description: 'Filter dependencies by projects within the group.'

      def preloads
        {
          name: [:component],
          version: [:component_version],
          component_version: [:component_version]
        }
      end

      private

      alias_method :group, :object

      def dependencies(params)
        result = if params[:project_ids].present?
                   params = params.merge(project_ids: resolve_gids(params[:project_ids], ::Project))
                   ::Sbom::DependenciesFinder.new(group, params: mapped_params(params)).execute
                 else
                   ::Sbom::AggregationsFinder.new(group, params: mapped_params(params)).execute
                 end

        apply_lookahead(result)
      end
    end
  end
end
