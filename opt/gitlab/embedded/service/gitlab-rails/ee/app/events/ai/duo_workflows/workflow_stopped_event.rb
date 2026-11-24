# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Published when a user cancels a Duo agent session. Sibling of
    # WorkflowFailedEvent: same payload, different reason the session ended, so a
    # subscriber picks the one it cares about instead of reading a status field.
    class WorkflowStoppedEvent < ::Gitlab::EventStore::CloudEvent
      event_category :duo_agent_platform
      event_type :workflow_stopped

      class << self
        def build(workflow:)
          build_cloud_event(
            source: "ai/duo_workflows/workflows/#{workflow.id}",
            subject: "ai/duo_workflows/workflows/#{workflow.id}",
            event_data: {
              workflow_id: workflow.id,
              workflow_definition: workflow.workflow_definition,
              adapter: workflow.messaging_callback_adapter
            }
          )
        end
      end

      def data_schema
        {
          'type' => 'object',
          'required' => %w[workflow_id],
          'properties' => {
            'workflow_id' => { 'type' => 'integer' },
            'workflow_definition' => { 'type' => %w[string null] },
            'adapter' => { 'type' => %w[string null] }
          },
          'additionalProperties' => false
        }
      end
    end
  end
end
