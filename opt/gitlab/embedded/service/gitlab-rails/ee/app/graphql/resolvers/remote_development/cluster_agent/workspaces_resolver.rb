# frozen_string_literal: true

module Resolvers
  module RemoteDevelopment
    module ClusterAgent
      class WorkspacesResolver < WorkspacesBaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type Types::RemoteDevelopment::WorkspaceType.connection_type, null: true
        authorize :admin_cluster
        authorizes_object!

        alias_method :agent, :object

        # @param [Hash] args
        # @return [RemoteDevelopment::Workspace::ActiveRecord_Relation]
        def resolve_with_lookahead(**args)
          apply_lookahead(
            ::RemoteDevelopment::WorkspacesFinder.execute(
              current_user: current_user,
              agent_ids: [agent.id],
              ids: resolve_ids(args[:ids]).map(&:to_i),
              project_ids: resolve_ids(args[:project_ids]).map(&:to_i),
              actual_states: args[:actual_states] || []
            )
          )
        end
      end
    end
  end
end
