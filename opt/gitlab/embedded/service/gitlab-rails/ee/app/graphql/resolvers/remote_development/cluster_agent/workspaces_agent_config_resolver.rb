# frozen_string_literal: true

module Resolvers
  module RemoteDevelopment
    module ClusterAgent
      class WorkspacesAgentConfigResolver < ::Resolvers::BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include LooksAhead

        type Types::RemoteDevelopment::WorkspacesAgentConfigType, null: true

        alias_method :agent, :object

        # @param [Hash] _args Not used
        # @return [WorkspacesAgentConfig]
        def resolve_with_lookahead(**_args)
          unless License.feature_available?(:remote_development)
            raise_resource_not_available_error! "'remote_development' licensed feature is not available"
          end

          raise Gitlab::Access::AccessDeniedError unless can_read_workspaces_agent_config?

          BatchLoader::GraphQL.for(agent.id).batch do |agent_ids, loader|
            agent_configs = ::RemoteDevelopment::AgentConfigsFinder.execute(
              current_user: current_user,
              cluster_agent_ids: agent_ids
            )
            apply_lookahead(agent_configs).each do |agent_config|
              # noinspection RubyResolve -- https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-32301
              loader.call(agent_config.cluster_agent_id, agent_config)
            end
          end
        end

        private

        # @return [TrueClass, FalseClass]
        def can_read_workspaces_agent_config?
          # noinspection RubyNilAnalysis - This is because the superclass #current_user uses #[], which can return nil
          Ability.allowed?(current_user, :read_cluster_agent, agent)
        end
      end
    end
  end
end
