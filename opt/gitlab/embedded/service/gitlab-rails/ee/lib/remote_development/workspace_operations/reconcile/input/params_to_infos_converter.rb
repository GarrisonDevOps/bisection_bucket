# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Input
        class ParamsToInfosConverter
          # @param [Hash] context
          # @return [Hash]
          def self.convert(context)
            context => { workspace_agent_info_hashes_from_params: Array => workspace_agent_info_hashes_from_params }

            # Convert the workspace_agent_info_hashes_from_params array into an array of AgentInfo objects
            workspace_agent_infos_by_name =
              workspace_agent_info_hashes_from_params.each_with_object({}) do |agent_info_hash_from_params, hash|
                agent_info = Factory.build(agent_info_hash_from_params: agent_info_hash_from_params)
                hash[agent_info.name.to_sym] = agent_info
              end

            context.merge(workspace_agent_infos_by_name: workspace_agent_infos_by_name)
          end
        end
      end
    end
  end
end
