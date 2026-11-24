# frozen_string_literal: true

module Ai
  module Messaging
    # Sole EventStore subscriber for messaging-lifecycle events (@GitLabDuo note
    # replies and Slack): resolves the adapter from the workflow's
    # messaging_callback_context and fires the matching lifecycle hook inline.
    # A delegated session's outcome goes to its parent's surface (see ChildSession).
    # Marked as having external dependencies because some adapters (e.g. Slack)
    # call third-party APIs.
    #
    # rubocop:disable Scalability/IdempotentWorker -- EventStore::Subscriber includes idempotent
    class CallbackWorker
      include Gitlab::EventStore::Subscriber
      include ::Ai::Messaging::ResultDelivery

      feature_category :duo_agent_platform

      # :sticky is the preferred consistency for jobs that should run as fast as possible: replicas
      # are guaranteed caught up to the enqueue point and the job falls back to the primary otherwise,
      # so there is no reschedule delay on replica lag.
      data_consistency :sticky
      worker_has_external_dependencies!

      # Without this the DeliveryRetryError and ApprovalRetryError raises would inherit Sidekiq's default 25.
      sidekiq_options retry: 3

      sidekiq_retries_exhausted do |job, exception|
        # Array.wrap: Subscriber can batch the data arg. error_class says what
        # exhausted the shared retry budget (a dropped delivery vs anything else).
        data = Array.wrap(job['args'].second).first.to_h

        Gitlab::AppLogger.warn(
          message: 'Duo Messaging: retries exhausted; giving up',
          error_class: exception&.class&.name,
          workflow_id: data['workflow_id'],
          workload_id: data['workload_id']
        )

        new.report_undelivered_result(data) if exception.is_a?(DeliveryRetryError)
      end

      # The answer never reached the surface, so tell the user instead of leaving the
      # run looking unfinished. Sidekiq swallows raises from the exhausted hook, so
      # errors are tracked here.
      def report_undelivered_result(data)
        workflow = workflow_for(data)
        return unless workflow

        with_adapter(workflow) do |adapter, callback_context|
          deliver_failure(adapter, callback_context, workflow, :delivery_failed)
        end
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: data['workflow_id'], workload_id: data['workload_id'])
      end

      def handle_event(event)
        case event
        when ::Ci::Workloads::WorkloadFinishedEvent
          handle_workload_finished(event)
        when ::Ai::DuoWorkflows::WorkflowStartedEvent
          handle_workflow_started(event)
        # Handled before it is subscribed, so a job queued by the release that moves messaging onto this event still
        # delivers on a node that has not got it yet.
        when ::Ai::DuoWorkflows::WorkflowFinishedEvent, ::Ai::DuoWorkflows::WorkflowFinishedCloudEvent
          handle_workflow_finished(event)
        when ::Ai::DuoWorkflows::WorkflowFailedEvent
          handle_workflow_terminated(event, terminal_error_for(event))
        # Handled before it is subscribed: 19.6 moves messaging sessions onto this
        # event, and a job it queues can run on a node still on 19.5.
        when ::Ai::DuoWorkflows::WorkflowStoppedEvent
          handle_workflow_terminated(event, :flow_stopped)
        when ::Ai::DuoWorkflows::WorkflowApprovalRequiredEvent
          handle_workflow_approval_required(event)
        when ::Ai::DuoWorkflows::WorkflowInputRequiredEvent
          handle_workflow_input_required(event)
        end
      end

      private

      def handle_workload_finished(event)
        workload = ::Ci::Workloads::Workload.find_by_id(event.data[:workload_id])
        unless workload
          log_skip('Workload not found', workload_id: event.data[:workload_id])
          return
        end

        workflow = workload.latest_workflow
        unless workflow
          log_skip('No workflow associated with workload', workload_id: event.data[:workload_id])
          return
        end

        with_adapter(workflow) do |adapter, callback_context|
          # On CI a pause ends the job cleanly; claiming here would swallow the real answer later.
          if workflow.awaiting_user?
            log_skip('Workload ended while the session waits on the user', workflow_id: workflow.id)
            next
          end

          if event.data[:status] == 'finished' || workflow.finished?
            # Success normally rides the earlier WorkflowFinishedEvent; this is the last
            # event for the run, so it is the backstop when that delivery never landed.
            deliver_success(adapter, callback_context, workflow)
          else
            deliver_failure(adapter, callback_context, workflow, workload_failure_for(workload, workflow))
          end
        end

        session = ::Ai::Messaging::ChildSession.from_workflow(workflow)
        return unless session

        if workflow.awaiting_user?
          log_skip('Workload ended while the session waits on the user', workflow_id: workflow.id)
          return
        end

        if event.data[:status] == 'finished' || workflow.finished?
          deliver_child_outcome(session)
        else
          deliver_child_outcome(session, error: workload_failure_for(workload, workflow))
        end
      end

      # A delegated session's claim is held per kind of ending, so this must name the
      # ending the workflow's own event did, or the outcome is posted twice. A session that has
      # not ended yet is ended by UpdateWorkflowStatusEventWorker from the pipeline, so read it too.
      def workload_failure_for(workload, workflow)
        return :flow_stopped if workflow.stopped?
        return :flow_failed if workflow.failed?

        workload.pipeline.canceled? ? :flow_stopped : :flow_failed
      end

      def handle_workflow_finished(event)
        with_workflow(event) do |workflow|
          with_adapter(workflow) do |adapter, callback_context|
            deliver_success(adapter, callback_context, workflow)
          end

          session = ::Ai::Messaging::ChildSession.from_workflow(workflow)
          deliver_child_outcome(session) if session
        end
      end

      def handle_workflow_started(event)
        with_workflow(event) do |workflow|
          with_adapter(workflow) do |adapter, callback_context|
            handle_error do
              adapter.on_flow_started(callback_context: callback_context, workflow: workflow)
            end
          end
        end
      end

      def terminal_error_for(event)
        event.event_data[:status_event] == 'stop' ? :flow_stopped : :flow_failed
      end

      def handle_workflow_terminated(event, error)
        with_workflow(event) do |workflow|
          with_adapter(workflow) do |adapter, callback_context|
            deliver_failure(adapter, callback_context, workflow, error)
          end

          session = ::Ai::Messaging::ChildSession.from_workflow(workflow)
          deliver_child_outcome(session, error: error) if session
        end
      end

      def handle_workflow_approval_required(event)
        with_workflow(event) do |workflow|
          with_adapter(workflow) do |adapter, callback_context|
            rendered = handle_error do
              adapter.on_approval_required(callback_context: callback_context, workflow: workflow)
            end
            next if rendered

            log_skip('Approval card not delivered; raising for Sidekiq retry', workflow_id: workflow.id)
            raise ApprovalRetryError, "Approval card delivery failed for workflow #{workflow.id}"
          end
        end
      end

      def handle_workflow_input_required(event)
        with_workflow(event) do |workflow|
          with_adapter(workflow) do |adapter, callback_context|
            handle_error do
              adapter.on_input_required(callback_context: callback_context, workflow: workflow)
            end

            # A detached turn ends at this pause, and nothing else delivers its answer. The
            # status check skips an event that arrives once the next turn is running.
            if callback_context[::Ai::Messaging::Adapters::Base::DETACHED_TURN_KEY] && workflow.input_required?
              deliver_success(adapter, callback_context, workflow)
            end
          end
        end
      end

      def workflow_for(data)
        if data['workflow_id']
          ::Ai::DuoWorkflows::Workflow.find_by_id(data['workflow_id'])
        else
          ::Ci::Workloads::Workload.find_by_id(data['workload_id'])&.latest_workflow
        end
      end

      def with_workflow(event)
        workflow_id = event.event_data[:workflow_id]

        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        unless workflow
          log_skip('Workflow not found', workflow_id: workflow_id)
          return
        end

        yield(workflow)
      end
    end
    # rubocop:enable Scalability/IdempotentWorker
  end
end
