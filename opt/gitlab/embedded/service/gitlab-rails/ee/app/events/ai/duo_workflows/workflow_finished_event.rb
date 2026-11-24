# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Published when a workflow transitions to :finished (agent completed
    # successfully). Only emitted for messaging-triggered workflows. Lets
    # @GitLabDuo/Slack replies be delivered at finish time instead of waiting for
    # the later Ci::Workloads::WorkloadFinishedEvent (CI pipeline finalization).
    #
    # Deprecated: will be replaced by WorkflowFinishedCloudEvent once the messaging
    # CallbackWorker moves to it.
    class WorkflowFinishedEvent < ::Gitlab::EventStore::Event
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
