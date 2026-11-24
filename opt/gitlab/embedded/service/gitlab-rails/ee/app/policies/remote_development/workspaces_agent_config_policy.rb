# frozen_string_literal: true

module RemoteDevelopment
  class WorkspacesAgentConfigPolicy < BasePolicy
    condition(:can_read_cluster_agent) { can?(:read_cluster_agent, agent) }

    # noinspection RubyResolve -- https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-32336
    rule { can_read_cluster_agent }.enable :read_workspaces_agent_config

    private

    # @return [Clusters::Agent]
    def agent
      @subject.agent
    end
  end
end
