# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Persistence
        class OrphanedWorkspacesObserver
          # @param [Hash] context
          # @return [void]
          def self.observe(context)
            context => {
              agent: agent, # Skip type checking so we can use fast_spec_helper in the unit test spec
              update_type: String => update_type,
              workspace_agent_infos_by_name: Hash => workspace_agent_infos_by_name,
              workspaces_from_agent_infos: Array => workspaces_from_agent_infos,
              logger: logger, # Skip type checking to avoid coupling to Rails logger
            }

            orphaned_workspace_agent_infos = detect_orphaned_workspaces(
              workspace_agent_infos_by_name: workspace_agent_infos_by_name,
              persisted_workspace_names: workspaces_from_agent_infos.map(&:name)
            )

            if orphaned_workspace_agent_infos.present?
              logger.warn(
                message:
                  "Received orphaned workspace agent info for workspace(s) where no persisted workspace record exists",
                error_type: "orphaned_workspace",
                agent_id: agent.id,
                update_type: update_type,
                count: orphaned_workspace_agent_infos.length,
                orphaned_workspaces: orphaned_workspace_agent_infos.map do |agent_info|
                  {
                    name: agent_info.name,
                    namespace: agent_info.namespace,
                    actual_state: agent_info.actual_state
                  }
                end
              )
            end

            nil
          end

          # @param [Hash] workspace_agent_infos_by_name
          # @param [Array] persisted_workspace_names
          # @return [Array]
          def self.detect_orphaned_workspaces(workspace_agent_infos_by_name:, persisted_workspace_names:)
            workspace_agent_infos_by_name.reject do |name, _|
              persisted_workspace_names.include?(name.to_s)
            end.values
          end
          private_class_method :detect_orphaned_workspaces
        end
      end
    end
  end
end
