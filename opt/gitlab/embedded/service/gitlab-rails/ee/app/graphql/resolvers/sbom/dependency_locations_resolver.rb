# frozen_string_literal: true

module Resolvers
  module Sbom
    class DependencyLocationsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include LooksAhead

      type Types::Sbom::DependencyLocationType.connection_type, null: true

      authorize :read_dependency
      authorizes_object!

      argument :component_version_id, ::Types::GlobalIDType[::Sbom::ComponentVersion],
        required: true,
        description: 'Global ID of the component version to find locations for.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Filter locations by file path.'

      alias_method :group, :object

      def resolve_with_lookahead(component_version_id:, search: nil)
        component_version_id = component_version_id.model_id

        occurrences = ::Sbom::Occurrence
          .filter_by_search_with_component_and_group(search, component_version_id, group)
          .with_dependency_paths_existence

        apply_lookahead(occurrences)
      end

      private

      def preloads
        {
          project: [{ project: [namespace: :route] }]
        }
      end
    end
  end
end
