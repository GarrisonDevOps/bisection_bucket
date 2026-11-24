# frozen_string_literal: true

module Resolvers
  module Sbom
    class DependencyTrackedRefsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::Sbom::DependencyTrackedRefType.connection_type, null: true

      authorize :read_dependency
      authorizes_object!

      argument :component_version_id, ::Types::GlobalIDType[::Sbom::ComponentVersion],
        required: true,
        description: 'Global ID of the component version to find refs for.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Filter refs by name.'

      alias_method :project, :object

      def resolve(component_version_id:, search: nil)
        return unless Feature.enabled?(:vulnerabilities_across_contexts, project.root_namespace)

        ::Sbom::DependencyTrackedRefsFinder.new(
          project,
          current_user,
          {
            component_version_id: component_version_id.model_id,
            search: search
          }
        ).execute
      end
    end
  end
end
