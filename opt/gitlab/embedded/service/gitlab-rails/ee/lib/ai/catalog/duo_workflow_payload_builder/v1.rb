# frozen_string_literal: true

module Ai
  module Catalog
    module DuoWorkflowPayloadBuilder
      class V1 < Base
        extend ::Gitlab::Utils::Override

        FLOW_VERSION = 'v1'
        AGENT_COMPONENT_TYPE = 'AgentComponent'
        DEFAULT_INPUTS = [
          { 'from' => 'context:goal', 'as' => 'goal' },
          { 'from' => 'context:project_id', 'as' => 'project' }
        ].freeze
        ORBIT_ENABLED_INPUT = {
          'from' => 'context:inputs.orbit_context.orbit_enabled',
          'as' => 'orbit_enabled',
          'optional' => true
        }.freeze
        ORBIT_CONTEXT_FLOW_INPUT = {
          'category' => 'orbit_context',
          'input_schema' => {
            'orbit_enabled' => {
              'type' => 'boolean',
              'description' => 'Whether Orbit is available for this user'
            }
          }
        }.freeze
        DUO_FLOW_TIMEOUT = 30
        PLACEHOLDER_VALUE = 'history'

        override :initialize
        def initialize(flow, pinned_version_prefix:, flow_environment:, params: {})
          @flow_environment = flow_environment

          super(flow, pinned_version_prefix:, params:)
        end

        private

        attr_reader :flow_environment

        def build_flow_config
          {
            'version' => FLOW_VERSION,
            'environment' => flow_environment,
            'components' => build_components,
            'routers' => build_routers,
            'flow' => flow_configuration,
            'prompts' => build_prompt_components
          }
        end

        def build_components
          steps.filter_map do |step|
            build_agent_component(step)
          end
        end

        def build_routers
          routers = []

          steps.each_cons(2) do |current_step, next_step|
            routers << {
              'from' => step_unique_identifier(current_step),
              'to' => step_unique_identifier(next_step)
            }
          end

          routers << {
            'from' => step_unique_identifier(steps.last),
            'to' => 'end'
          }
        end

        def build_prompt_components
          steps.filter_map do |step|
            prompt_component(step)
          end
        end

        def flow_configuration
          config = { 'entry_point' => step_unique_identifier(steps.first) }
          config['inputs'] = [ORBIT_CONTEXT_FLOW_INPUT] if steps.any? { |step| step[:agent].foundational_chat_agent? }
          config
        end

        def build_agent_component(step)
          definition = step[:definition]

          {
            'name' => step_unique_identifier(step),
            'type' => AGENT_COMPONENT_TYPE,
            'prompt_id' => step_prompt_id(step),
            'inputs' => agent_inputs(step),
            'toolset' => agent_toolset(definition),
            'ui_log_events' => ui_log_events
          }
        end

        def agent_inputs(step)
          inputs = DEFAULT_INPUTS
          inputs += [ORBIT_ENABLED_INPUT] if step[:agent].foundational_chat_agent?
          return inputs if step[:idx] == 0

          previous_step = steps[step[:idx] - 1]
          previous_step_id = step_unique_identifier(previous_step)

          inputs + [
            {
              'from' => "context:#{previous_step_id}.final_answer",
              'as' => 'previous_agent_answer'
            },
            {
              'from' => "conversation_history:#{previous_step_id}",
              'as' => 'previous_agent_chat'
            }
          ]
        end

        def prompt_component(step)
          definition = step[:definition]

          {
            'prompt_id' => step_prompt_id(step),
            'name' => step_unique_identifier(step),
            'unit_primitives' => [],
            'prompt_template' => {
              'system' => system_prompt(definition),
              'user' => user_prompt(definition),
              'placeholder' => PLACEHOLDER_VALUE
            },
            'params' => {
              'timeout' => DUO_FLOW_TIMEOUT
            }
          }
        end

        def agent_toolset(definition)
          definition.tool_names
        end

        # Required for rendering agent outputs on the UI
        def ui_log_events
          %w[
            on_tool_execution_success
            on_agent_final_answer
            on_tool_execution_failed
          ]
        end

        def user_prompt(definition)
          params[:user_prompt_input] || definition.user_prompt
        end

        def system_prompt(definition)
          definition.system_prompt
        end
      end
    end
  end
end
