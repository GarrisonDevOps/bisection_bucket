# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Input
        class AgentInfosObserver
          NORMAL = "normal"
          ABNORMAL = "abnormal"

          # @param [Hash] context
          # @return [void]
          def self.observe(context)
            context => {
              agent: agent, # Skip type checking so we can use fast_spec_helper in the unit test spec
              update_type: String => update_type,
              workspace_agent_infos_by_name: Hash => workspace_agent_infos_by_name,
              logger: logger, # Skip type checking to avoid coupling to Rails logger
            }

            abnormal_agent_infos, normal_agent_infos =
              workspace_agent_infos_by_name.values.partition do |agent_info|
                [States::UNKNOWN, States::ERROR].include? agent_info.actual_state
              end

            normal_count = normal_agent_infos.length
            abnormal_count = abnormal_agent_infos.length
            total_count = normal_count + abnormal_count

            # Log normal agent infos at debug level
            logger.debug(
              message: "Parsed #{total_count} total workspace agent infos from params, with " \
                "#{normal_count} in a NORMAL actual_state and #{abnormal_count} in an ABNORMAL actual_state",
              agent_id: agent.id,
              update_type: update_type,
              actual_state_type: NORMAL,
              total_count: total_count,
              normal_count: normal_count,
              abnormal_count: abnormal_count,
              normal_agent_infos: normal_agent_infos.map do |agent_info|
                {
                  name: agent_info.name,
                  namespace: agent_info.namespace,
                  actual_state: agent_info.actual_state,
                  deployment_resource_version: agent_info.deployment_resource_version
                }
              end,
              abnormal_agent_infos: abnormal_agent_infos.map do |agent_info|
                {
                  name: agent_info.name,
                  namespace: agent_info.namespace,
                  actual_state: agent_info.actual_state,
                  deployment_resource_version: agent_info.deployment_resource_version
                }
              end
            )

            # Log abnormal agent infos at warn level
            if abnormal_agent_infos.present?
              logger.warn(
                message: "Parsed #{abnormal_count} workspace agent infos with an " \
                  "ABNORMAL actual_state from params (total: #{total_count})",
                error_type: "abnormal_actual_state",
                agent_id: agent.id,
                update_type: update_type,
                actual_state_type: ABNORMAL,
                total_count: total_count,
                normal_count: normal_count,
                abnormal_count: abnormal_count,
                abnormal_agent_infos: abnormal_agent_infos.map do |agent_info|
                  {
                    name: agent_info.name,
                    namespace: agent_info.namespace,
                    actual_state: agent_info.actual_state,
                    deployment_resource_version: agent_info.deployment_resource_version
                  }
                end
              )
            end

            nil
          end
        end
      end
    end
  end
end
