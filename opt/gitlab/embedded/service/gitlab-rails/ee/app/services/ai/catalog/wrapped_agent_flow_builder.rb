# frozen_string_literal: true

module Ai
  module Catalog
    class WrappedAgentFlowBuilder
      include Gitlab::Utils::StrongMemoize

      GENERATED_FLOW_VERSION = '1.0.0'

      def initialize(agent, agent_version)
        @agent = agent
        @agent_version = agent_version
        @flow = nil
      end

      def execute
        return validate if validate.error?

        build_flow_from_agent

        return validate_flow if validate_flow.error?

        ServiceResponse.success(payload: { flow: flow })
      end

      private

      attr_reader :agent, :agent_version, :flow

      def validate
        return error('Agent is required') unless agent && agent.agent?
        return error('Agent version is required') unless agent_version

        return error('Agent version must belong to the agent') unless agent_version.item == agent

        ServiceResponse.success
      end
      strong_memoize_attr :validate

      def build_flow_from_agent
        @flow = build_flow_item
        flow_version = build_flow_version
        @flow.latest_version = flow_version
        @flow.versions = [flow_version]
        @flow.readonly!
      end

      def build_flow_item
        ::Ai::Catalog::Item.flow.new(
          name: "Generated Flow for #{agent.name}",
          description: "Auto-generated flow from agent #{agent.name}",
          organization: agent.organization
        )
      end

      def build_flow_version
        # Internally generated flow not authored by the user, so DWS validation is not required.
        # We can safely mark dws_flow_config_validated as true.
        ::Ai::Catalog::ItemVersion.new(
          item: flow,
          definition: build_flow_definition,
          schema_version: ::Ai::Catalog::ItemVersion::AGENT_REFERENCED_FLOW_SCHEMA_VERSION,
          version: GENERATED_FLOW_VERSION,
          dws_flow_config_validated: true
        )
      end

      def build_flow_definition
        {
          triggers: [],
          steps: [
            {
              agent_id: agent.id,
              current_version_id: agent_version.id,
              pinned_version_prefix: agent_version.version
            }
          ]
        }
      end

      def validate_flow
        return error("Generated flow is invalid: #{flow.errors.full_messages.join(', ')}") unless flow.valid?

        ServiceResponse.success
      end
      strong_memoize_attr :validate_flow

      def error(message)
        ServiceResponse.error(message: Array(message))
      end
    end
  end
end
