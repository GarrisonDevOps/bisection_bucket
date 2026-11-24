# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      module DesiredConfig
        class Main
          # @param [Hash] parent_context
          # @return [Hash]
          def self.main(parent_context)
            parent_context => {
              params: params,
              workspace: workspace,
              logger: logger
            }

            context = {
              workspace_id: workspace.id,
              workspace_name: workspace.name,
              workspace_namespace: workspace.namespace,
              workspace_desired_state_is_running: workspace.desired_state_running?,
              workspaces_agent_id: params[:agent].id,
              workspaces_agent_config: workspace.workspaces_agent_config,
              processed_devfile_yaml: workspace.processed_devfile,
              logger: logger,
              desired_config_array: [],
              project_path: workspace.project.path
            }

            initial_result = Gitlab::Fp::Result.ok(context)

            result =
              initial_result
                .map(ConfigValuesExtractor.method(:extract))
                .map(DevfileParserGetter.method(:get))
                .map(DesiredConfigYamlParser.method(:parse))
                .map(DevfileResourceModifier.method(:modify))
                .map(DevfileResourceAppender.method(:append))
                .map(
                  ->(context) do
                    context.merge(
                      desired_config:
                        RemoteDevelopment::WorkspaceOperations::DesiredConfig.new(
                          desired_config_array: context.fetch(:desired_config_array)
                        )
                    )
                  end
                )

            parent_context[:desired_config] = result.unwrap.fetch(:desired_config)

            parent_context
          end
        end
      end
    end
  end
end
