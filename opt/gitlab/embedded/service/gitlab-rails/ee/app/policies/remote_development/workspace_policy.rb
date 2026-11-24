# frozen_string_literal: true

module RemoteDevelopment
  # noinspection RubyResolve - https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-25400
  class WorkspacePolicy < BasePolicy
    condition(:can_access_workspaces_feature) { can?(:access_workspaces_feature, :global) }
    condition(:can_admin_cluster_agent_for_workspace) { can?(:admin_cluster, workspace.agent) }
    condition(:is_workspace_owner) { user&.id == workspace.user_id }
    condition(:can_read_own_workspace) { can?(:_read_own_workspace, workspace.project) }
    condition(:can_update_own_workspace) { can?(:_update_own_workspace, workspace.project) }

    rule { ~can_access_workspaces_feature }.policy do
      prevent :read_workspace
      prevent :update_workspace
    end

    rule { admin }.enable :read_workspace
    rule { admin }.enable :update_workspace

    rule { is_workspace_owner & can_read_own_workspace }.enable :read_workspace
    rule { is_workspace_owner & can_update_own_workspace }.enable :update_workspace

    rule { can_admin_cluster_agent_for_workspace }.enable :read_workspace
    rule { can_admin_cluster_agent_for_workspace }.enable :update_workspace

    private

    # @return [RemoteDevelopment::Workspace]
    def workspace
      subject
    end
  end
end
