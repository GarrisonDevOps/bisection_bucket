# frozen_string_literal: true

module Ai
  module Catalog
    module Tracking
      # Builds the flow or agent identity of a session, using the property names of the
      # `trigger_ai_catalog_item` event so both data sources can be compared directly.
      class WorkflowIdentityPropertiesBuilder
        IDENTITY_KEYS = %i[item_type item_version item_schema_version flow_name component_name custom_item_id].freeze

        # Matches EVENT_FOUNDATIONAL_AGENT_FLOW_NAME in ee/app/assets/javascripts/ai/catalog/constants.js
        FOUNDATIONAL_AGENT_FLOW_NAME = 'chat'

        # @param workflow [Ai::DuoWorkflows::Workflow]
        def initialize(workflow)
          @workflow = workflow
        end

        # @return [Hash] identity properties with nil values removed
        def to_h
          properties = catalog_item_properties || foundational_flow_properties || foundational_agent_properties

          properties.to_h.slice(*IDENTITY_KEYS).compact
        end

        private

        attr_reader :workflow

        def catalog_item_properties
          version = workflow.ai_catalog_item_version
          return unless version

          # EventPropertiesBuilder has no foundational agent type, so it would return no identity.
          if version.item.foundational_chat_agent?
            return agent_properties(::Ai::FoundationalChatAgent.for_catalog_item(version.item.id))
          end

          EventPropertiesBuilder.new(item: version.item, version: version).to_h
        end

        # A GitLab flow whose catalog item is not seeded on this instance.
        def foundational_flow_properties
          flow = ::Ai::Catalog::FoundationalFlow.find_by_reference(workflow.workflow_definition) # rubocop:disable Gitlab/Ai/AvoidFoundationalFlowStringLookup -- dynamic, session-provided reference
          return unless flow

          name, schema_version = flow.foundational_flow_reference.split('/', 2)

          {
            item_type: 'foundational_flow',
            item_version: flow.flow_version,
            item_schema_version: schema_version,
            flow_name: name
          }
        end

        def foundational_agent_properties
          return unless ::Ai::FoundationalChatAgent.foundational_workflow_definition?(workflow.workflow_definition)

          agent_properties(::Ai::FoundationalChatAgent.with_workflow_definition(workflow.workflow_definition))
        end

        def agent_properties(agent)
          {
            item_type: 'foundational_agent',
            item_version: agent.flow_version.presence,
            item_schema_version: agent.version.presence,
            flow_name: FOUNDATIONAL_AGENT_FLOW_NAME,
            component_name: agent.reference
          }
        end
      end
    end
  end
end
