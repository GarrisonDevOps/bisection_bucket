# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class WorkspaceAgentkStateCreator
        include Messages

        # @param [Hash] context
        # @return [void]
        def self.create(context)
          context => {
            workspace: Workspace => workspace,
            # NOTE: This has to be fully qualified or the class will not be found
            desired_config: ::RemoteDevelopment::WorkspaceOperations::DesiredConfig => desired_config,
            logger: logger
          }

          unless desired_config.valid?
            logger.error(
              message: "desired_config is invalid",
              error_type: "workspace_agentk_state_error",
              workspace_id: workspace.id,
              validation_error: desired_config.errors.full_messages
            )
          end

          workspace_agentk_state = WorkspaceAgentkState.create!(
            workspace: workspace,
            project: workspace.project,
            desired_config: desired_config.symbolized_desired_config_array
          )

          if workspace_agentk_state.errors.present?
            return Gitlab::Fp::Result.err(
              WorkspaceAgentkStateCreateFailed.new({ errors: workspace_agentk_state.errors, context: context })
            )
          end

          Gitlab::Fp::Result.ok(context)
        end
      end
    end
  end
end
