# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Output
        class ResponsePayloadBuilder
          include UpdateTypes

          ALL_RESOURCES_INCLUDED = :all_resources_included
          PARTIAL_RESOURCES_INCLUDED = :partial_resources_included
          NO_RESOURCES_INCLUDED = :no_resources_included

          # @param [Hash] context
          # @return [Hash]
          def self.build(context)
            context => {
              update_type: String => update_type,
              workspaces_to_be_returned: Array => workspaces_to_be_returned,
              settings: {
                full_reconciliation_interval_seconds: Integer => full_reconciliation_interval_seconds,
                partial_reconciliation_interval_seconds: Integer => partial_reconciliation_interval_seconds
              },
              logger: logger
            }

            observability_for_rails_infos = {}

            # Create an array of workspace_rails_info hashes based on the workspaces. These indicate the desired updates
            # to the workspace, which will be returned in the payload to the agent to be applied to kubernetes
            workspace_rails_infos = workspaces_to_be_returned.map do |workspace|
              config_to_apply, config_to_apply_resources_include_type = generate_config_to_apply(workspace: workspace,
                update_type: update_type, logger: logger)
              observability_for_rails_infos = {
                name: workspace.name,
                config_to_apply_resources_include_type: config_to_apply_resources_include_type
              }

              config_to_apply_yaml_stream =
                # config_to_apply_yaml will be returned as nil if generate_config_to_apply returned nil
                if config_to_apply
                  # Dump the config_to_apply to yaml with stringified keys, so it can be sent to the agent. This is
                  # the last time we will have access to it before it is returned to the agent in the reconciliation
                  # response, so we have kept everything as a hash with symbolized keys until now.
                  config_to_apply.map { |resource| YAML.dump(resource.deep_stringify_keys) }.join
                else
                  # Return an empty string, which is valid YAML to represent a YAML `stream` with "zero" documents:
                  # https://yaml.org/spec/1.2.2/#streams
                  ""
                end

              {
                name: workspace.name,
                namespace: workspace.namespace,
                desired_state: workspace.desired_state,
                actual_state: workspace.actual_state,
                deployment_resource_version: workspace.deployment_resource_version,
                config_to_apply: config_to_apply_yaml_stream,
                image_pull_secrets: workspace.workspaces_agent_config.image_pull_secrets.map(&:symbolize_keys)
              }
            end

            settings = {
              full_reconciliation_interval_seconds: full_reconciliation_interval_seconds,
              partial_reconciliation_interval_seconds: partial_reconciliation_interval_seconds
            }

            context.merge(
              response_payload: {
                workspace_rails_infos: workspace_rails_infos,
                settings: settings
              },
              observability_for_rails_infos: observability_for_rails_infos
            )
          end

          # @param [RemoteDevelopment::Workspace] workspace
          # @param [String (frozen)] update_type
          # @param [RemoteDevelopment::Logger] logger
          # @return [Array]
          def self.generate_config_to_apply(workspace:, update_type:, logger:)
            return nil, NO_RESOURCES_INCLUDED unless should_include_config_to_apply?(update_type: update_type,
              workspace: workspace)

            include_all_resources = should_include_all_resources?(update_type: update_type, workspace: workspace)
            resources_include_type = include_all_resources ? ALL_RESOURCES_INCLUDED : PARTIAL_RESOURCES_INCLUDED

            desired_config = DesiredConfigFetcher.fetch(workspace: workspace, logger: logger)
            config_to_apply_array = ConfigToApplyBuilder.build(
              workspace: workspace,
              include_all_resources: include_all_resources,
              desired_config: desired_config
            )

            if workspace.workspace_agentk_state
              # Leverage the DesiredConfig Value Object to ensure that config_to_apply is valid
              DesiredConfig.new(desired_config_array: config_to_apply_array).validate!
            end

            stable_sorted_workspace_resources = config_to_apply_array.map do |resource|
              Gitlab::Utils.deep_sort_hash(resource)
            end

            return nil, NO_RESOURCES_INCLUDED unless stable_sorted_workspace_resources.present?

            [stable_sorted_workspace_resources, resources_include_type]
          end

          # @param [String (frozen)] update_type
          # @param [RemoteDevelopment::Workspace] workspace
          # @return [Boolean]
          def self.should_include_config_to_apply?(update_type:, workspace:)
            update_type == FULL ||
              workspace.force_include_all_resources ||
              workspace.desired_state_updated_more_recently_than_last_response_to_agent? ||
              workspace.actual_state_updated_more_recently_than_last_response_to_agent? ||
              workspace.desired_state_terminated_and_actual_state_not_terminated?
          end

          # @param [String (frozen)] update_type
          # @param [RemoteDevelopment::Workspace] workspace
          # @return [Boolean]
          def self.should_include_all_resources?(update_type:, workspace:)
            update_type == FULL ||
              workspace.force_include_all_resources ||
              # We include all resources if actual_state_updated_more_recently_than_last_response_to_agent?,
              # so that the file secret for WORKSPACE_RECONCILED_ACTUAL_STATE_FILE_PATH is always updated when
              # the actual_state changes
              workspace.actual_state_updated_more_recently_than_last_response_to_agent?
          end

          private_class_method :generate_config_to_apply, :should_include_config_to_apply?,
            :should_include_all_resources?
        end
      end
    end
  end
end
