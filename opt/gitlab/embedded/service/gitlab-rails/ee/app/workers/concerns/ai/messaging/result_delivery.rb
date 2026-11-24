# frozen_string_literal: true

module Ai
  module Messaging
    # Delivering a flow's terminal outcome to the surface that triggered it.
    # Shared by the two workers that can reach that point: CallbackWorker, from
    # the workflow's status events, and ServerSideTurnWorker, for a Workhorse
    # turn it waited on.
    #
    # The claim is what keeps them from delivering twice, so any new caller must
    # go through deliver_success rather than calling the adapter directly.
    module ResultDelivery
      extend ActiveSupport::Concern

      # Raised after a failed delivery so Sidekiq owns the retry. Inheriting
      # RetryError keeps the expected retry out of Sentry and the execution SLI;
      # the underlying adapter error was already tracked once at its source.
      DeliveryRetryError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

      # Same retry treatment, but exhaustion must not claim the delivery: the run is
      # still paused and can be approved from GitLab, after which the answer still
      # has to reach this surface.
      ApprovalRetryError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

      private

      def with_adapter(workflow)
        callback_context = workflow.messaging_callback_context
        return unless callback_context.present?

        klass = ::Ai::Messaging::AdapterRegistry[callback_context['adapter']]
        unless klass
          Gitlab::AppLogger.warn(
            message: 'Duo Messaging: unknown adapter in callback context',
            adapter: callback_context['adapter'],
            workflow_id: workflow.id
          )
          return
        end

        yield(klass.from_callback_context(callback_context), callback_context)
      end

      # Deliveries can land mid-delivery of each other -- the fast path and the
      # backstop for a CI flow, a retry and the original elsewhere -- so the
      # atomic claim picks one winner. Only the failing job knows its delivery
      # failed, so it raises for its own Sidekiq retry.
      def deliver_success(adapter, callback_context, workflow)
        if already_delivered?(workflow)
          log_skip('Terminal outcome already delivered', workflow_id: workflow.id)
          return
        end

        # Read before claiming: this checkpoint read is not error-wrapped, and a raise
        # after a claim would strand it (the retry would then skip at the guard above).
        message = extract_final_message(workflow.latest_ui_chat_log)

        unless workflow.claim_messaging_callback_delivery
          # The holder owns the outcome either way: success needs nothing from us, and
          # failure raises for its own Sidekiq retry. Stand down.
          log_skip('Delivery claimed by concurrent job', workflow_id: workflow.id)
          return
        end

        unless message
          # The final checkpoint is persisted before the run pauses or finishes, so a
          # message missing now stays missing: the claim is kept because the outcome is
          # settled whether or not the error itself reaches the user.
          handle_error do
            adapter.on_flow_failed(callback_context: callback_context, error: :no_response, workflow: workflow)
          end

          return
        end

        delivered = handle_error do
          adapter.deliver_result(callback_context: callback_context, message: message, workflow: workflow)
        end

        unless delivered
          # on_flow_completed is held back so the surface isn't marked answered
          # with no answer on it. Release BEFORE raising:
          # the Sidekiq retry re-enters handle_event and must pass the guard above.
          workflow.release_messaging_callback_delivery!
          log_skip('Result delivery failed; released claim for Sidekiq retry', workflow_id: workflow.id)

          raise DeliveryRetryError, "Result delivery failed for workflow #{workflow.id}"
        end

        handle_error { adapter.on_flow_completed(callback_context: callback_context, workflow: workflow) }
      end

      # A dropped CI session fails twice (WorkflowFailedEvent + failed WorkloadFinishedEvent); the claim picks one.
      def deliver_failure(adapter, callback_context, workflow, error)
        if already_delivered?(workflow)
          log_skip('Terminal outcome already delivered', workflow_id: workflow.id)
          return
        end

        unless workflow.claim_messaging_callback_delivery
          log_skip('Delivery claimed by concurrent job', workflow_id: workflow.id)
          return
        end

        handle_error do
          adapter.on_flow_failed(callback_context: callback_context, error: error, workflow: workflow)
        end
      end

      # Same claim-then-deliver shape as deliver_success, but the claim lives with the
      # child session: a delegated session has no messaging context to hold it.
      def deliver_child_outcome(session, error: nil)
        child = session.child
        message = extract_final_message(child.latest_ui_chat_log) unless error

        unless session.claim_result_delivery(error)
          log_skip('Delegated session outcome already delivered', workflow_id: child.id)
          return
        end

        delivered = handle_error { session.deliver_result(message: message, error: error) }
        return if delivered

        session.release_result_delivery!(error)
        log_skip('Delegated session outcome delivery failed; released claim for Sidekiq retry', workflow_id: child.id)

        raise DeliveryRetryError, "Delegated session outcome delivery failed for workflow #{child.id}"
      end

      def already_delivered?(workflow)
        workflow.messaging_callback_context['delivered_at'].present?
      end

      # The ui_chat_log is cumulative: the latest checkpoint contains the full
      # log. Search from the end for the last agent message with non-blank
      # content and no tool calls, so that a trailing empty or tool-call-only
      # agent turn (e.g. after a final tool call like marking todos complete)
      # does not suppress the real response.
      def extract_final_message(chat_log)
        chat_log.reverse_each.detect do |m|
          m['message_type'] == 'agent' && m['content'].present? && m['tool_calls'].blank?
        end&.dig('content')
      end

      def log_skip(reason, **identifiers)
        Gitlab::AppLogger.info(
          message: "Duo Messaging: #{reason}",
          **identifiers
        )
      end

      # Returns nil once it swallows an error, so deliver_success reads a raised
      # delivery the same way it reads an adapter reporting one: not delivered.
      def handle_error
        yield
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e)
        nil
      end
    end
  end
end
