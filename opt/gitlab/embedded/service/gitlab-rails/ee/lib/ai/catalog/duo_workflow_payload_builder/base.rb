# frozen_string_literal: true

module Ai
  module Catalog
    module DuoWorkflowPayloadBuilder
      class Base
        include Gitlab::Utils::StrongMemoize
        include ActiveModel::Model

        def initialize(flow, pinned_version_prefix:, params: {})
          @flow = flow
          @pinned_version_prefix = pinned_version_prefix
          @params = params
        end

        def build
          validate_inputs!
          build_flow_config
        end

        private

        attr_reader :flow, :pinned_version_prefix, :params

        def validate_inputs!
          raise ArgumentError, 'Flow is required' if flow.nil?
          raise ArgumentError, 'Flow must be an Ai::Catalog::Item' unless flow.is_a?(::Ai::Catalog::Item)
          raise ArgumentError, 'Flow must have item_type of flow' unless flow.flow?
        end

        def pinned_to_specific_version?
          # if the flow is pinned to a specific version, we pin all agent versions too
          pinned_version_prefix.to_s.count('.') == 2
        end

        def flow_definition
          flow.definition(pinned_version_prefix)
        end
        strong_memoize_attr :flow_definition

        def steps
          @steps ||= flow_definition.steps.map do |step|
            step.merge(definition: agent_definition_for_step(step))
          end
        end

        def agent_definition_for_step(step)
          agent = step[:agent]
          pinned_version_id = pinned_to_specific_version? ? step[:current_version_id] : nil
          agent.definition(step[:pinned_version_prefix], pinned_version_id)
        end

        def step_unique_identifier(step)
          step[:unique_id]
        end

        def step_prompt_id(step)
          "#{step_unique_identifier(step)}_prompt"
        end
      end
    end
  end
end
