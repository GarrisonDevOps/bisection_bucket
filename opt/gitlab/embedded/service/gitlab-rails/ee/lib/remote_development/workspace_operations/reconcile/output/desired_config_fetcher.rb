# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Output
        class DesiredConfigFetcher
          # @param workspace [RemoteDevelopment::Workspace]
          # @param logger [RemoteDevelopment::Logger]
          # @return [RemoteDevelopment::WorkspaceOperations::DesiredConfig]
          def self.fetch(workspace:, logger:)
            workspace_agentk_state = workspace.workspace_agentk_state

            if workspace_agentk_state
              desired_config_array = workspace_agentk_state.desired_config
              desired_config = RemoteDevelopment::WorkspaceOperations::DesiredConfig.new(
                desired_config_array: desired_config_array
              )
              # If the workspace_agentk_state.desired_config_array was somehow persisted to the database in an invalid
              #  state, this will raise an exception. We validate it before saving, so this should never happen normally
              desired_config.validate!
              return desired_config
            end

            # TODO: remove this and the above 'if' after a successful shadow run. Issue - https://gitlab.com/gitlab-org/gitlab/-/issues/551935
            generate_new_desired_config(workspace: workspace, logger: logger)
          end

          # @param [RemoteDevelopment::Workspace] workspace
          # @param [RemoteDevelopment::Logger] logger
          # @return [RemoteDevelopment::WorkspaceOperations::DesiredConfig]
          def self.generate_new_desired_config(workspace:, logger:)
            result = Create::DesiredConfig::Main.main(
              {
                params: {
                  agent: workspace.agent
                },
                workspace: workspace,
                logger: logger
              }
            )

            result => {
              desired_config: RemoteDevelopment::WorkspaceOperations::DesiredConfig => desired_config,
            }

            desired_config
          end

          private_class_method :generate_new_desired_config
        end
      end
    end
  end
end
