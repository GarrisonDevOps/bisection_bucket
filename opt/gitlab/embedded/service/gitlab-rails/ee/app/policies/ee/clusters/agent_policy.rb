# frozen_string_literal: true

module EE
  module Clusters
    module AgentPolicy
      extend ActiveSupport::Concern

      prepended do
        # noinspection RubyResolve -- https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-32336
        condition(:organization_workspaces_authorized_agent, score: 10) do
          organization = @subject.project.organization
          organization.user?(@user) && @subject.unversioned_latest_workspaces_agent_config&.enabled &&
            @subject.organization_cluster_agent_mapping&.organization_id == organization.id
        end

        rule { organization_workspaces_authorized_agent }.policy do
          enable :read_cluster_agent
          enable :create_workspace
        end
      end
    end
  end
end
