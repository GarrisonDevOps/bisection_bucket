# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CleanStuckWorkflowsService
      include ::Services::ReturnServiceResponses
      include ::Gitlab::InternalEventsTracking
      include Concerns::WorkflowEventTracking

      EXPIRATION_IN_MINUTES = 30
      BATCH_LIMIT = 1000

      AUDIT_EVENT_NAME = 'duo_session_failed'
      AUDIT_EVENT_MESSAGE = 'Duo session failed: stuck session cleaned up after timeout'

      STUCK_WORKFLOWS_COUNTER = Gitlab::Metrics.counter(
        :gitlab_duo_workflow_stuck_workflows_cleaned_total,
        'Total number of stuck Duo Workflow sessions cleaned up, by original status and flow type'
      )

      CLEAN_FAILURES_COUNTER = Gitlab::Metrics.counter(
        :gitlab_duo_workflow_stuck_workflows_clean_failed_total,
        'Total number of stuck Duo Workflow sessions that could not be cleaned up, by original status and flow type'
      )

      def execute
        scope = Ai::DuoWorkflows::Workflow.with_status(:created, :running)
                  .stale_since(EXPIRATION_IN_MINUTES.minutes.ago)
                  .preload(:user, :project, :namespace) # rubocop:disable CodeReuse/ActiveRecord -- one-off preload for this cleanup loop, not worth a model scope
        iterator = Gitlab::Pagination::Keyset::Iterator.new(scope: scope)

        # Batched around the whole run, not around each workflow: the total-counter keys are
        # per event name, so they are identical for every workflow here. Flushing per workflow
        # would write the same 4 keys every time and save nothing.
        Gitlab::InternalEvents.with_batched_redis_writes do
          iterator.each_batch(of: BATCH_LIMIT) do |workflows|
            workflows.to_a.each do |w|
              original_status = w.status_name
              w.drop_reason = 'no_activity'

              if w.drop
                track_fail(w, original_status)
              else
                track_clean_failure(w, original_status)
              end
            end
          end
        end

        success(:processed)
      end

      private

      def track_fail(workflow, original_status)
        STUCK_WORKFLOWS_COUNTER.increment(
          status: original_status.to_s,
          flow_type: workflow.workflow_definition.to_s
        )

        track_internal_event(
          "cleanup_stuck_agent_platform_session",
          user: workflow.user,
          project: workflow.project,
          namespace: workflow.namespace,
          additional_properties: {
            label: workflow.workflow_definition,
            value: workflow.id,
            property: workflow.drop_reason
          }
        )

        # `drop` bypasses UpdateWorkflowStatusService, so emit the terminal event here too.
        # Without it a stuck session is only ever recorded as created + started and goes
        # missing from the completion rate, which reads event 20 for `dropped_event_at`.
        track_workflow_event("agent_platform_session_dropped", workflow)

        audit_fail(workflow)
        publish_status_change(workflow)
      end

      # `drop` returns false when the transition cannot be saved, usually a validation the row
      # started failing after it was written. Without this the session stays stuck forever while
      # the cron silently retries it every 30 minutes.
      def track_clean_failure(workflow, original_status)
        CLEAN_FAILURES_COUNTER.increment(
          status: original_status.to_s,
          flow_type: workflow.workflow_definition.to_s
        )

        Gitlab::AppLogger.warn(
          message: 'duo_workflow_stuck_cleanup_failed',
          workflow_id: workflow.id,
          workflow_definition: workflow.workflow_definition,
          original_status: original_status.to_s,
          validation_errors: workflow.errors.full_messages
        )
      end

      # `drop` also bypasses the subscription trigger in UpdateWorkflowStatusService.
      def publish_status_change(workflow)
        GraphqlTriggers.workflow_events_updated(workflow.present.latest_checkpoint || workflow)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
      end

      def audit_fail(workflow)
        audit_context = {
          name: AUDIT_EVENT_NAME,
          author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: workflow.project || workflow.namespace,
          target: workflow,
          target_details: "#{workflow.workflow_definition} session #{workflow.id}",
          message: AUDIT_EVENT_MESSAGE
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
      end
    end
  end
end
