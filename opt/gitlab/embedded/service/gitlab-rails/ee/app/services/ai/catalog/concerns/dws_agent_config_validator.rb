# frozen_string_literal: true

module Ai
  module Catalog
    module Concerns
      module DwsAgentConfigValidator
        extend ActiveSupport::Concern
        include DwsFlowConfigValidator

        private

        def build_agent_flow_config(definition)
          ::Ai::Catalog::DuoWorkflowPayloadBuilder::V1AgentDefinitionWrapper.new(
            definition, params: { user_prompt_input: Agents::BuildFlowConfigService::USER_PROMPT_INPUT }
          ).build
        end

        def validate_agent_config_with_dws(definition)
          validate_flow_config_with_dws(build_agent_flow_config(definition))
        end
      end
    end
  end
end
