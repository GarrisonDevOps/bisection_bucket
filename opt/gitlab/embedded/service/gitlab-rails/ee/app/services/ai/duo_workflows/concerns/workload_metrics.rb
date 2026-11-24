# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module Concerns
      module WorkloadMetrics
        extend ActiveSupport::Concern
        include ::Gitlab::InternalEventsTracking

        private

        def track_workload_completion_metrics(workflow, workload:)
          return unless workflow && workload

          failure_reason = workload.failure_reason

          track_internal_event(
            'duo_workflow_workload_completed',
            user: workflow.user,
            project: workflow.project,
            additional_properties: {
              label: workload.runtime_status,
              property: failure_reason,
              value: workload.duration,
              workflow_id: workflow.id.to_s,
              workflow_definition: workflow.workflow_definition
            }.compact
          )

          Gitlab::AppLogger.info(
            message: 'duo_workflow_workload_completed',
            failure_reason: failure_reason,
            workflow_id: workflow.id,
            workflow_definition: workflow.workflow_definition,
            project_id: workflow.project&.id,
            **workload.log_context
          )
        end
      end
    end
  end
end
