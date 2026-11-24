# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Published when a Duo agent session completes successfully. Sibling of
    # WorkflowFailedEvent and WorkflowStoppedEvent: same payload, the third way a
    # session ends, so a subscriber picks the one it cares about. Fires at finish
    # rather than waiting for the later Ci::Workloads::WorkloadFinishedEvent, so a
    # @GitLabDuo or Slack reply lands as soon as the agent is done.
    # Published for every session, whatever it was running, so subscribers filter
    # themselves with an `if:` guard rather than the publisher guessing who cares.
    # A new class rather than a reshaped WorkflowFinishedEvent, so a job queued by one
    # release never runs against the other release's schema.
    class WorkflowFinishedCloudEvent < ::Gitlab::EventStore::CloudEvent
      event_category :duo_agent_platform
      event_type :workflow_finished

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
