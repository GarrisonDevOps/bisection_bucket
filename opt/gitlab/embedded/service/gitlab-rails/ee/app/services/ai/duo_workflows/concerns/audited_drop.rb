# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module Concerns
      # A bare `drop` bypasses UpdateWorkflowStatusService and takes the workflow out of
      # CleanStuckWorkflowsService's scope, so the terminal event, audit and subscription update are
      # emitted here instead.
      module AuditedDrop
        extend ActiveSupport::Concern
        include WorkflowEventTracking

        DROP_AUDIT_EVENT_NAME = 'duo_session_failed'

        private

        def drop_and_audit(workflow, drop_reason:, author:, message:)
          workflow.drop_reason = drop_reason

          return unless workflow.drop

          track_workflow_event('agent_platform_session_dropped', workflow)
          audit_dropped_workflow(workflow, author: author, message: message)
          publish_status_change(workflow)
        end

        def publish_status_change(workflow)
          GraphqlTriggers.workflow_events_updated(workflow.present.latest_checkpoint || workflow)
        rescue StandardError => error
          ::Gitlab::ErrorTracking.track_exception(error, workflow_id: workflow.id)
        end

        def audit_dropped_workflow(workflow, author:, message:)
          ::Gitlab::Audit::Auditor.audit(
            name: DROP_AUDIT_EVENT_NAME,
            author: author,
            scope: workflow.project || workflow.namespace,
            target: workflow,
            target_details: "#{workflow.workflow_definition} session #{workflow.id}",
            message: message
          )
        rescue StandardError => error
          ::Gitlab::ErrorTracking.track_exception(error, workflow_id: workflow.id)
        end
      end
    end
  end
end
