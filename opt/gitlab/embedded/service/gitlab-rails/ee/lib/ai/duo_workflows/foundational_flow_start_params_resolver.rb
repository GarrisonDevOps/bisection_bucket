# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class FoundationalFlowStartParamsResolver
      def self.call(reference, container, user: nil, additional_context: nil)
        flow = ::Ai::Catalog::FoundationalFlow.find_by_reference(reference)
        return resolve_for_foundational_chat_agent(reference) unless flow

        flow.resolve_flow_version_for(container: container, user: user, additional_context: additional_context)
      end

      def self.resolve_for_foundational_chat_agent(reference)
        agent = ::Ai::FoundationalChatAgent.with_workflow_definition(reference)
        return {} unless agent&.flow_version

        config_id, schema_version = reference.split('/', 2)

        {
          flow_config_id: config_id,
          flow_config_schema_version: schema_version.presence,
          flow_version: agent.flow_version
        }
      end
    end
  end
end
