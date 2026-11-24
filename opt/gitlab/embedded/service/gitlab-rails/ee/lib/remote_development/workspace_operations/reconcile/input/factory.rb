# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Input
        class Factory
          # @param [Hash] agent_info_hash_from_params
          # @return [RemoteDevelopment::WorkspaceOperations::Reconcile::Input::AgentInfo]
          def self.build(agent_info_hash_from_params:)
            # Hash#[] instead of Hash#fetch or destructuring is used, since the field may not be present
            latest_k8s_deployment_info = agent_info_hash_from_params[:latest_k8s_deployment_info]

            actual_state = ActualStateCalculator.calculate_actual_state(
              latest_k8s_deployment_info: latest_k8s_deployment_info,
              # workspace_agent_info.fetch('termination_progress') is not used since the field may not be present
              termination_progress: agent_info_hash_from_params[:termination_progress],
              latest_error_details: agent_info_hash_from_params[:error_details]
            )

            deployment_resource_version = latest_k8s_deployment_info&.dig(:metadata, :resourceVersion)

            # If the actual state of the workspace is Terminated, the only keys which will be put into the
            # AgentInfo object are name and actual_state
            info = {
              name: agent_info_hash_from_params.fetch(:name),
              actual_state: actual_state,
              namespace: agent_info_hash_from_params.fetch(:namespace),
              deployment_resource_version: deployment_resource_version
            }

            AgentInfo.new(**info)
          end
        end
      end
    end
  end
end
