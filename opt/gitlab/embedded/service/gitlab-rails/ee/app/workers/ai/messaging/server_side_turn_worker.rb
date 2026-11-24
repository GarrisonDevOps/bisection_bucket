# frozen_string_literal: true

module Ai
  module Messaging
    # Runs one turn of a server-side flow for a messaging surface and delivers
    # its answer.
    #
    # Unlike most workers this one blocks for the whole turn, unless the turn
    # is detached (below): it holds the HTTP connection to Workhorse, which
    # holds the gRPC stream to the Duo Workflow Service. That is the job. It exists as a worker of its own, rather than
    # inline in the surface's event worker, so the run is not bounded by that
    # worker's own retry semantics and so its fleet concurrency can be capped.
    # Live progress flows through ProgressDeliveryWorker, driven by the
    # checkpoints the flow writes as it runs.
    #
    # With duo_workflow_detached_server_side_execution, the job only starts the
    # turn: Workhorse answers once the run has started and keeps it going on its
    # own, and CallbackWorker delivers the outcome from the workflow's status
    # events. Calling Workhorse from the callers instead is not an option,
    # because some of them are web requests, which must not call back into
    # Rails through Workhorse and wait for the answer.
    #
    # rubocop:disable Scalability/IdempotentWorker -- a turn is not idempotent: re-running resumes the flow from its last checkpoint
    # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- a user is waiting on this turn, and the session's writes come from DWS through the API, which is never deferred
    class ServerSideTurnWorker
      include ApplicationWorker
      include ::Ai::Messaging::ResultDelivery
      include ::Ai::DuoWorkflows::Concerns::AuditedDrop

      DROP_AUDIT_EVENT_MESSAGE = 'Duo session failed: server-side turn did not succeed'
      SYSTEM_AUTHOR = ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)')

      # Workhorse turned the turn down before starting it, so starting it again is safe.
      TurnNotStartedError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)
      WorkflowLockedError = Class.new(TurnNotStartedError)
      WorkhorseUnavailableError = Class.new(TurnNotStartedError)

      TURN_NOT_STARTED_ERRORS = {
        workflow_locked: WorkflowLockedError,
        workhorse_unavailable: WorkhorseUnavailableError
      }.freeze
      TURN_START_RETRIES = 3

      feature_category :duo_agent_platform
      data_consistency :sticky
      urgency :low
      worker_has_external_dependencies!

      # A user is waiting, so retry for a minute or two rather than on Sidekiq's backoff.
      sidekiq_retry_in do |count, exception|
        next unless exception.is_a?(TurnNotStartedError)

        count < TURN_START_RETRIES ? 10 * (count + 1) : :kill
      end

      sidekiq_retries_exhausted do |job, exception|
        new.report_turn_not_started(job['args'].first, exception) if exception.is_a?(TurnNotStartedError)
      end

      # Each job pins a Sidekiq thread for a whole turn, so the usual assumption
      # that jobs are short does not hold. Provisional until real traffic informs
      # a better number: sidekiq_concurrency_limit_queue_jobs, labelled by worker,
      # reports how many turns are waiting on this limit.
      concurrency_limit -> { 50 }

      # A turn interrupted by a deploy is re-pushed by Sidekiq and resumes from
      # the flow's last checkpoint, so a duplicate job is wasteful rather than
      # harmful; Workhorse rejects the second one while the first still holds the
      # workflow lock.
      deduplicate :until_executed

      # goal is the message this turn is answering. It is absent for the first
      # turn, whose message is the workflow's own goal, and present for every
      # turn after it: a session's goal stays the message that opened it, the
      # way it does for a chat session driven from a browser.
      #
      # options carries the turn's run context (ExecuteRunService::CONTEXT_KEYS).
      def perform(workflow_id, approval = nil, goal = nil, options = {})
        result = run_turn(workflow_id, approval, goal, options)

        # A turn that started released the claim when the session resumed. Not in an
        # ensure: a raise keeps the claim for the retry, which runs the same turn.
        ::Ai::DuoWorkflows::TurnClaim.new(workflow_id).release unless result&.success?
      end

      # Sidekiq only logs raises from the exhausted hook, so errors are tracked here.
      def report_turn_not_started(workflow_id, error)
        # The raise kept the claim for a retry, and none is left.
        ::Ai::DuoWorkflows::TurnClaim.new(workflow_id).release

        # The hook runs outside the job's sticky session, and a stale status from a
        # replica would claim the delivery over the running turn's answer.
        workflow = find_workflow_on_primary(workflow_id)
        return unless workflow
        # The run holding the lock delivers its own outcome; a failure would claim it.
        return if error.is_a?(WorkflowLockedError) && workflow.running?

        reason = error.is_a?(WorkflowLockedError) ? :workflow_locked : :execute_workflow_failed

        if workflow.messaging_callback_context.blank?
          drop_failed_turn(workflow, ServiceResponse.error(message: error.message, reason: reason))
          return
        end

        with_adapter(workflow) do |adapter, callback_context|
          deliver_failure(adapter, callback_context, workflow, reason)
        end
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow_id)
      end

      private

      def run_turn(workflow_id, approval, goal, options)
        # A signal left by an earlier stop must not stop this turn. Cleared
        # before the workflow is read, so a stop that lands after the read
        # sets it again, and a stop that lands before is caught below.
        ::Gitlab::DuoWorkflow::WorkhorseStopSignal.clear(workflow_id)

        workflow = find_workflow_on_primary(workflow_id)
        return if workflow.nil? || skip_turn?(workflow)

        detached = Feature.enabled?(:duo_workflow_detached_server_side_execution, workflow.user)
        rerun = turn_started?(workflow)
        result = execute_turn(workflow, approval, goal, options, detached: detached, rerun: rerun)

        # The turn is still going; CallbackWorker delivers its outcome.
        return result if result.success? && result.payload[:detached]

        # A run parked on an approval has produced no answer yet, and the surface
        # cannot answer it until the approval work lands. Delivering the last
        # message here would also claim the delivery and so suppress the real
        # answer once the run resumes and finishes.
        return result if result.success? && workflow.awaiting_approval?

        if result.error? && TURN_NOT_STARTED_ERRORS.key?(result.reason)
          return retry_turn(workflow, result, detached: detached, rerun: rerun)
        end

        if result.error? && workflow.messaging_callback_context.blank?
          drop_failed_turn(workflow, result)
          return result
        end

        with_adapter(workflow) do |adapter, callback_context|
          next deliver_success(adapter, callback_context, workflow) if result.success?

          deliver_failure(adapter, callback_context, workflow, result.reason || :flow_failed)
        end

        result
      end

      # A sticky replica only has writes from before the enqueue, so it can miss
      # a stop that landed since and whose signal the clear above just removed.
      def find_workflow_on_primary(workflow_id)
        ::Gitlab::Database::LoadBalancing::SessionMap
          .current(::Ai::DuoWorkflows::Workflow.load_balancer)
          .use_primary { ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id) }
      end

      def skip_turn?(workflow)
        # Failed or stopped while queued; that outcome is already delivered, so
        # running now would only resume the session for an answer that gets dropped.
        if workflow.status_terminal?
          log_skip('Session already terminal; not running the turn', workflow_id: workflow.id)
          return true
        end

        # A retry whose turn already ran and was answered; ExecuteRunService clears the
        # claim before it enqueues a new turn.
        return false unless workflow.messaging_callback_context.present? && already_delivered?(workflow)

        log_skip('Turn already delivered; not running it again', workflow_id: workflow.id)
        true
      end

      # A rerun is Sidekiq running the job again (a retry or a deploy re-push) after
      # the run took the turn's message. ai-gateway reads a goal or approval sent at a
      # wait as the user's next reply, so a rerun sends neither.
      def execute_turn(workflow, approval, goal, options, detached:, rerun:)
        if rerun && turn_ended?(workflow)
          # Answered, but not delivered; only the delivery is left to retry.
          return ServiceResponse.success(payload: { workflow: workflow })
        end

        # Before the request: a detached turn can pause before Workhorse even answers.
        mark_turn_started(workflow, detached)

        ::Ai::DuoWorkflows::ServerSideExecutionService.new(
          workflow: workflow,
          goal: (goal.presence || workflow.goal unless rerun),
          approval: (approval unless rerun),
          context: options.symbolize_keys.slice(*::Ai::DuoWorkflows::ExecuteRunService::CONTEXT_KEYS),
          detached: detached
        ).execute
      end

      def retry_turn(workflow, result, detached:, rerun:)
        # A running detached turn delivers its own outcome. It is this job's own run
        # from before Sidekiq re-pushed it, or a concurrent message's turn, which
        # leaves this message unanswered rather than suppressing that turn's answer.
        if result.reason == :workflow_locked && detached && workflow.reset.running?
          log_skip('Workflow locked by a running detached turn', workflow_id: workflow.id)
          return
        end

        # Nothing started, so the retry hands the message over. A rerun keeps the
        # marker: an earlier attempt's run already took the message.
        clear_turn_started(workflow) unless rerun

        raise TURN_NOT_STARTED_ERRORS.fetch(result.reason), result.message
      end

      def turn_started?(workflow)
        workflow.messaging_callback_context.present? &&
          workflow.messaging_callback_context[::Ai::Messaging::Adapters::Base::TURN_STARTED_KEY].present?
      end

      def turn_ended?(workflow)
        ::Ai::DuoWorkflows::ServerSideExecutionService::TURN_END_STATUS_GROUPS.include?(workflow.status_group)
      end

      # Without a messaging context there is no marker, so a rerun hands the message
      # over again. If pre-authorization does not grant a detached run, Workhorse
      # streams the turn, both workers try to deliver it and the claim picks one.
      def mark_turn_started(workflow, detached)
        return if workflow.messaging_callback_context.blank?

        marker = { ::Ai::Messaging::Adapters::Base::TURN_STARTED_KEY => true }
        marker[::Ai::Messaging::Adapters::Base::DETACHED_TURN_KEY] = true if detached

        workflow.merge_messaging_callback_context!(marker)
      end

      # Undoes mark_turn_started: this attempt started no run, detached or not.
      def clear_turn_started(workflow)
        return if workflow.messaging_callback_context.blank?

        workflow.merge_messaging_callback_context!(
          ::Ai::Messaging::Adapters::Base::TURN_STARTED_KEY => nil,
          ::Ai::Messaging::Adapters::Base::DETACHED_TURN_KEY => nil
        )
      end

      # A session no surface reports on, such as a trigger's, would otherwise stay running
      # until CleanStuckWorkflowsService drops it. A locked workflow is another turn's, still running.
      def drop_failed_turn(workflow, result)
        return if result.reason == :workflow_locked

        # DWS may have failed the session already, and a paused session stays resumable after a
        # transient failure, as it does for CleanStuckWorkflowsService.
        workflow.reset
        return unless workflow.created? || workflow.running?

        # A bare drop, as CreateAndStartWorkflowService does: a forbidden turn means the user
        # may no longer pass UpdateWorkflowStatusService's authorization.
        drop_reason = result.reason == :flow_failed ? 'no_status_reported' : 'start_failed'
        drop_and_audit(workflow, drop_reason: drop_reason, author: SYSTEM_AUTHOR, message: DROP_AUDIT_EVENT_MESSAGE)
      end
    end
    # rubocop:enable Scalability/IdempotentWorker
    # rubocop:enable Sidekiq/EnforceDatabaseHealthSignalDeferral
  end
end
