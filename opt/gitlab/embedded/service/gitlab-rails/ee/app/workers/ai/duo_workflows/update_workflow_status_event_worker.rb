# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # rubocop: disable Scalability/IdempotentWorker -- EventStore::Subscriber includes idempotent
    class UpdateWorkflowStatusEventWorker
      include Gitlab::EventStore::Subscriber
      include Concerns::WorkloadMetrics

      feature_category :duo_agent_platform
      data_consistency :delayed

      # Deliberately excludes the states where a human is expected to act
      # (paused, input_required, and the approval states), which `drop` also accepts.
      RECONCILABLE_STATUSES = %i[created running].freeze
      RECONCILE_SUMMARY = 'Session did not report a final status before its pipeline finished'

      def handle_event(event)
        workload = Ci::Workloads::Workload.find_by_id(event.data[:workload_id])
        return unless workload

        workflow = workload.workflows.last
        return unless workflow

        return if stale_workload_event?(workflow, workload)

        pipeline = workload.pipeline
        action = workload_action(event, pipeline)

        failure_reason = workload.failure_reason if action == 'drop'

        summary = "Error during Session: #{failure_reason}" if failure_reason

        if action == 'stop'
          result = UpdateWorkflowStatusService.new(workflow: workflow, status_event: action,
            current_user: workflow.user, skip_authorization: true).execute
        elsif action == 'drop'
          result = UpdateWorkflowStatusService.new(workflow: workflow, status_event: action,
            current_user: workflow.user, summary: summary, drop_reason: 'job_failed',
            skip_authorization: true).execute
        elsif RECONCILABLE_STATUSES.include?(workflow.status_name)
          # A workload that finished cleanly should have reported its own terminal status.
          # Still being created/running means that never arrived. Reconcile now: the cleanup
          # cron runs every 30 minutes and skips sessions stale for under 30, so up to an hour.
          result = UpdateWorkflowStatusService.new(workflow: workflow, status_event: 'drop',
            current_user: workflow.user, summary: RECONCILE_SUMMARY, drop_reason: 'no_status_reported',
            skip_authorization: true).execute
        end

        track_workload_completion_metrics(workflow, workload:)

        return unless failure_reason && result.success?

        # Ending the session skips the access check; sending its job log to the LLM must not.
        return unless Ability.allowed?(workflow.user, :update_duo_workflow, workflow)

        GenerateWorkflowSummaryWorker.perform_async(workflow.id)
      end

      private

      # A workload has no cancelled state: a cancelled CI job ends its workload as failed.
      # Read the pipeline so the session ends as stopped, not failed, when the agent in the
      # job could not report the stop itself (for example on a force cancel).
      def workload_action(event, pipeline)
        return 'finish' if event.data[:status].to_sym == :finished
        return 'stop' if pipeline.canceled?

        'drop'
      end

      # A session that has been retried has more than one workload. An event for an older one
      # must not decide the status of a session that has since moved to a newer workload, or we
      # mark a running session as failed. Logged rather than skipped quietly so we can see it happen.
      def stale_workload_event?(workflow, workload)
        last_workload_id = workflow.last_workload&.id
        return false if last_workload_id == workload.id

        Gitlab::AppLogger.info(
          message: 'duo_workflow_stale_workload_event_skipped',
          workflow_id: workflow.id,
          workload_id: workload.id,
          last_workload_id: last_workload_id
        )

        true
      end
    end
    # rubocop: enable Scalability/IdempotentWorker
  end
end
