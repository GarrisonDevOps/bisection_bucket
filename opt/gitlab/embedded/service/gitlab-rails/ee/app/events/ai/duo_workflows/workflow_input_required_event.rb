# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowInputRequiredEvent < ::Gitlab::EventStore::CloudEvent
      event_category :duo_agent_platform
      event_type :workflow_input_required

      class << self
        def build(workflow:)
          build_cloud_event(
            source: "ai/duo_workflows/workflows/#{workflow.id}",
            subject: "ai/duo_workflows/workflows/#{workflow.id}",
            event_data: { workflow_id: workflow.id }
          )
        end
      end

      def data_schema
        {
          'type' => 'object',
          'required' => %w[workflow_id],
          'properties' => {
            'workflow_id' => { 'type' => 'integer' }
          },
          'additionalProperties' => false
        }
      end
    end
  end
end
