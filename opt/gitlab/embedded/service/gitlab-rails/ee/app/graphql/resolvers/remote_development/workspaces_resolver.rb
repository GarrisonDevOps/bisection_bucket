# frozen_string_literal: true

module Resolvers
  module RemoteDevelopment
    class WorkspacesResolver < WorkspacesBaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::RemoteDevelopment::WorkspaceType.connection_type, null: true

      argument :agent_ids, [::Types::GlobalIDType[::Clusters::Agent]],
        required: false,
        description: 'Filter workspaces by agent GlobalIDs.'

      argument :include_actual_states, [GraphQL::Types::String],
        required: false,
        deprecated: { reason: 'Use actual_states instead', milestone: '16.7' },
        description: 'Filter workspaces by actual states.'

      # @param [Hash] args
      # @return [RemoteDevelopment::Workspace::ActiveRecord_Relation]
      def resolve_with_lookahead(**args)
        # noinspection RubyNilAnalysis - This is because the superclass #current_user uses #[], which can return nil
        # TODO: Change the superclass to use context.fetch(:current_user) instead of context[:current_user]
        apply_lookahead(
          ::RemoteDevelopment::WorkspacesFinder.execute(
            current_user: current_user,
            user_ids: [current_user.id],
            ids: resolve_ids(args[:ids]).map(&:to_i),
            project_ids: resolve_ids(args[:project_ids]).map(&:to_i),
            agent_ids: resolve_ids(args[:agent_ids]).map(&:to_i),
            actual_states: args[:actual_states] || args[:include_actual_states] || []
          )
        )
      end
    end
  end
end
