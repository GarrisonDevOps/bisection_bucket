# frozen_string_literal: true

module Ai
  module Catalog
    module Agents
      class BuildFlowConfigService < Ai::Catalog::BaseService
        include Gitlab::Utils::StrongMemoize

        CHAT_FLOW_TYPE = 'chat'
        USER_PROMPT_INPUT = 'Here is my task - {{goal}}'

        def initialize(project:, current_user:, params:)
          @agent_version = params[:agent_version]
          @agent = agent_version&.item
          @flow_config_type = params[:flow_config_type]
          super
        end

        def execute
          return validate unless validate.success?
          return error_no_permissions unless allowed?

          if flow_config_type == CHAT_FLOW_TYPE
            build_chat_flow_config
          else
            error('Invalid value for flow_config_type. Only "chat" is supported.')
          end
        end

        private

        attr_reader :agent, :agent_version, :flow_config_type

        def allowed?
          Ability.allowed?(current_user, :read_ai_catalog_item, agent_version)
        end

        def validate
          return error('Agent version is required') unless agent_version

          ServiceResponse.success
        end
        strong_memoize_attr :validate

        def build_chat_flow_config
          wrapped_agent_response = ::Ai::Catalog::WrappedAgentFlowBuilder.new(agent, agent_version).execute

          return wrapped_agent_response if wrapped_agent_response.error?

          flow = wrapped_agent_response.payload[:flow]
          payload_builder = ::Ai::Catalog::DuoWorkflowPayloadBuilder::V1AgentWrapper.new(
            flow,
            flow.latest_version,
            flow_environment: 'chat-partial',
            params: { user_prompt_input: USER_PROMPT_INPUT }
          )

          flow_config = payload_builder.build

          ServiceResponse.success(payload: { flow_config: flow_config.to_yaml })
        end
      end
    end
  end
end
