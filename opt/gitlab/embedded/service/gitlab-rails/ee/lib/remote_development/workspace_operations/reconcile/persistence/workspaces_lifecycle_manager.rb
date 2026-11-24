# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Persistence
        class WorkspacesLifecycleManager
          # @param [Hash] context
          # @return [Hash]
          def self.manage(context)
            context => {
              workspaces_from_agent_infos: Array => workspaces_from_agent_infos,
            }

            # Ensure workspaces do not exist indefinitely. This is a temporary approach, we eventually want
            # to replace this with some mechanism to detect workspace activity and only shut down inactive workspaces.
            # Until then, this is the workaround to ensure workspaces don't live indefinitely.
            # See https://gitlab.com/gitlab-org/gitlab/-/issues/390597
            workspaces_from_agent_infos.each do |workspace|
              # We don't care about workspaces that are already in desired_state of Terminated
              next if [States::TERMINATED].include?(workspace.desired_state)

              terminate_if_exceeded_max_hours_before_termination(workspace: workspace) ||
                stop_if_exceeded_max_active_hours_before_stop(workspace: workspace) ||
                terminate_if_exceeded_max_stopped_hours_before_termination(workspace: workspace)
            end

            context
          end

          # @param [RemoteDevelopment::Workspace] workspace
          # @return [Boolean] true if the condition matched and the workspace was updated, false if it was not
          def self.terminate_if_exceeded_max_hours_before_termination(workspace:)
            max_hours_before_termination = MaxHoursBeforeTermination::MAX_HOURS_BEFORE_TERMINATION

            return false unless (workspace.created_at + max_hours_before_termination.hours).past?

            workspace.update!(desired_state: States::TERMINATED)

            true
          end

          # @param [RemoteDevelopment::Workspace] workspace
          # @return [Boolean] true if the condition matched and the workspace was updated, false if it was not
          def self.stop_if_exceeded_max_active_hours_before_stop(workspace:)
            # We only want to stop "active" workspaces, which means in desired_state of RestartRequested or Running
            return false if workspace.desired_state_stopped?

            time_to_stop = workspace.desired_state_updated_at +
              workspace.workspaces_agent_config.max_active_hours_before_stop.hours
            return false unless time_to_stop.past?

            workspace.update!(desired_state: States::STOPPED)

            true
          end

          # @param [RemoteDevelopment::Workspace] workspace
          # @return [Boolean] true if the condition matched and the workspace was updated, false if it was not
          def self.terminate_if_exceeded_max_stopped_hours_before_termination(workspace:)
            # We only want to terminate stopped workspaces
            return false unless workspace.desired_state_stopped?

            hours_since_stop = (Time.zone.now - workspace.desired_state_updated_at) / 1.hour
            unless hours_since_stop > workspace.workspaces_agent_config.max_stopped_hours_before_termination
              return false
            end

            workspace.update!(desired_state: States::TERMINATED)

            true
          end

          private_class_method :terminate_if_exceeded_max_hours_before_termination,
            :stop_if_exceeded_max_active_hours_before_stop,
            :terminate_if_exceeded_max_stopped_hours_before_termination
        end
      end
    end
  end
end
