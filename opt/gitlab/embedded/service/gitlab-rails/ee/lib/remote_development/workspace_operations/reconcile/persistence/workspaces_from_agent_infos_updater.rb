# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Persistence
        class WorkspacesFromAgentInfosUpdater
          # @param [Hash] context
          # @return [Hash]
          def self.update(context)
            context => {
              agent: agent, # Skip type checking so we can use fast_spec_helper in the unit test spec
              workspace_agent_infos_by_name: Hash => workspace_agent_infos_by_name,
            }

            workspaces_from_agent_infos =
              agent.workspaces.by_names(workspace_agent_infos_by_name.keys).order_id_asc.to_a

            # Update persisted workspaces which match the names of the workspaces in the AgentInfo objects array
            workspaces_from_agent_infos.each do |persisted_workspace|
              workspace_agent_info = workspace_agent_infos_by_name.fetch(persisted_workspace.name.to_sym)
              # Update the persisted workspaces with the latest info from the AgentInfo objects we received
              update_persisted_workspace_with_latest_info(
                persisted_workspace: persisted_workspace,
                deployment_resource_version: workspace_agent_info.deployment_resource_version,
                actual_state: workspace_agent_info.actual_state
              )
            end

            context.merge(
              workspaces_from_agent_infos: workspaces_from_agent_infos
            )
          end

          # @param [RemoteDevelopment::Workspace] persisted_workspace
          # @param [String] deployment_resource_version
          # @param [String] actual_state
          # @return [void]
          def self.update_persisted_workspace_with_latest_info(
            persisted_workspace:,
            deployment_resource_version:,
            actual_state:
          )
            # Handle the special case of RESTART_REQUESTED. desired_state is only set to 'RESTART_REQUESTED' until the
            # actual_state is detected as 'STOPPED', then we switch the desired_state to 'RUNNING' so it will restart.
            # See: https://gitlab.com/gitlab-org/remote-development/gitlab-remote-development-docs/blob/main/doc/architecture.md?plain=0#possible-desired_state-values
            if persisted_workspace.desired_state_restart_requested? && actual_state == States::STOPPED
              persisted_workspace.desired_state = States::RUNNING
            end

            persisted_workspace.actual_state = actual_state

            # In some cases a deployment resource version may not be present, e.g. if the initial creation request for
            # workspace creation resulted in an Error.
            persisted_workspace.deployment_resource_version = deployment_resource_version if deployment_resource_version

            persisted_workspace.save!

            nil
          end
          private_class_method :update_persisted_workspace_with_latest_info
        end
      end
    end
  end
end
