# frozen_string_literal: true

module Resolvers
  module RemoteDevelopment
    class WorkspacesBaseResolver < ::Resolvers::BaseResolver
      include ResolvesIds
      include LooksAhead

      extras [:lookahead]

      type Types::RemoteDevelopment::WorkspaceType.connection_type, null: true

      argument :ids, [::Types::GlobalIDType[::RemoteDevelopment::Workspace]],
        required: false,
        description:
          'Filter workspaces by workspace GlobalIDs. For example, `["gid://gitlab/RemoteDevelopment::Workspace/1"]`.'

      argument :project_ids, [::Types::GlobalIDType[Project]],
        required: false,
        description: 'Filter workspaces by project GlobalIDs.'

      argument :actual_states, [GraphQL::Types::String],
        required: false,
        description: 'Filter workspaces by actual states.'

      # @param [Hash] args
      # @return [Boolean]
      def ready?(**args)
        # rubocop:disable Graphql/ResourceNotAvailableError -- Gitlab::Graphql::Authorize::AuthorizeResource is not included
        unless License.feature_available?(:remote_development)
          raise ::Gitlab::Graphql::Errors::ResourceNotAvailable,
            "'remote_development' licensed feature is not available"
        end
        # rubocop:enable Graphql/ResourceNotAvailableError

        super
      end

      # @return [Hash]
      def preloads
        {
          user_provided_workspace_variables: [:user_provided_workspace_variables]
        }
      end
    end
  end
end
