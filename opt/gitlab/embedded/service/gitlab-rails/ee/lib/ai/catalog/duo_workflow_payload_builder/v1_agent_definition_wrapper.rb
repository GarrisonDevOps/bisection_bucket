# frozen_string_literal: true

module Ai
  module Catalog
    module DuoWorkflowPayloadBuilder
      class V1AgentDefinitionWrapper < V1
        AGENT_NAME = 'agent'
        ENVIRONMENT = 'chat-partial'

        Definition = Struct.new(:system_prompt, :user_prompt, :tool_names)

        NON_FOUNDATIONAL_AGENT = Class.new do
          def foundational_chat_agent?
            false
          end
        end.new.freeze

        def initialize(definition, params: {})
          super(nil, pinned_version_prefix: nil, flow_environment: ENVIRONMENT, params: params)

          definition = definition.stringify_keys
          tool_ids = definition['tools']
          tool_names = ::Ai::Catalog::BuiltInTool.where(id: tool_ids).map(&:name) # rubocop:disable CodeReuse/ActiveRecord -- Not a database query

          @definition = Definition.new(
            definition['system_prompt'].to_s,
            definition['user_prompt'].to_s,
            tool_names
          )
        end

        private

        def validate_inputs!; end

        def steps
          @steps ||= [{ unique_id: AGENT_NAME, agent: NON_FOUNDATIONAL_AGENT, definition: @definition, idx: 0 }]
        end
      end
    end
  end
end
