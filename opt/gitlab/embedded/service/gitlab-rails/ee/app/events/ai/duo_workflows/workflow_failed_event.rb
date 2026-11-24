# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # In 19.5 this carries both endings of a session, for messaging sessions only,
    # told apart by `status_event`. In 19.6 a stop moves to WorkflowStoppedEvent and
    # this is published for every session, so 19.5 already builds and accepts both
    # payload shapes.
    class WorkflowFailedEvent < ::Gitlab::EventStore::CloudEvent
      event_category :duo_agent_platform
      event_type :workflow_failed

      class << self
        def build(workflow:, status_event: nil)
          build_cloud_event(
            source: "ai/duo_workflows/workflows/#{workflow.id}",
            subject: "ai/duo_workflows/workflows/#{workflow.id}",
            event_data: event_data_for(workflow, status_event)
          )
        end

        private

        def event_data_for(workflow, status_event)
          return { workflow_id: workflow.id, status_event: status_event.to_s } if status_event

          {
            workflow_id: workflow.id,
            workflow_definition: workflow.workflow_definition,
            adapter: workflow.messaging_callback_adapter
          }
        end
      end

      def data_schema
        {
          'type' => 'object',
          'required' => %w[workflow_id],
          'properties' => {
            'workflow_id' => { 'type' => 'integer' },
            'status_event' => { 'type' => 'string', 'enum' => %w[drop stop] },
            'workflow_definition' => { 'type' => %w[string null] },
            'adapter' => { 'type' => %w[string null] }
          },
          'additionalProperties' => false
        }
      end
    end
  end
end
