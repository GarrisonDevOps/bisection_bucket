# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Published when a workflow first transitions to :running (the agent has
    # actually begun executing inside the CI container after setup). Only
    # emitted for messaging-triggered workflows (those with a
    # messaging_callback_context).
    class WorkflowStartedEvent < ::Gitlab::EventStore::Event
      def schema
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
