# frozen_string_literal: true

module Ai
  module Messaging
    # Delivers live progress for a messaging-triggered workflow (e.g. Slack) to
    # its adapter. Enqueued per checkpoint but debounced per workflow, so a burst
    # collapses into one delivery and a quiet workflow does zero work.
    #
    # The dedup config is load-bearing:
    #   - including_scheduled: true -- REQUIRED, else scheduled (perform_in) jobs
    #     are not deduplicated and every checkpoint would deliver.
    #   - if_deduplicated: :reschedule_once -- a checkpoint arriving mid-delivery
    #     is not dropped; it reschedules once so the trailing frame still ships.
    # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- a frame debounced by 2s is stale by the time a deferral returns it
    class ProgressDeliveryWorker
      include ApplicationWorker

      # 2s: just above the observed p50 checkpoint cadence (~1.5s) and under
      # Slack's ~1 msg/s/channel limit. The perform_in delay is the debounce window.
      DEBOUNCE_INTERVAL = 2.seconds

      feature_category :duo_agent_platform
      data_consistency :delayed
      urgency :low
      deduplicate :until_executed, including_scheduled: true, if_deduplicated: :reschedule_once
      # External dependency on a high-frequency worker: cap fleet concurrency so a
      # surface incident can't exhaust Sidekiq capacity.
      concurrency_limit -> { 1000 }
      idempotent!
      worker_has_external_dependencies!

      def perform(workflow_id)
        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        return unless workflow

        callback_context = workflow.messaging_callback_context
        return if callback_context.blank?
        # Once the outcome is delivered it owns the surface; stop streaming so a
        # debounced/rescheduled tick can't re-render interim state on top of the
        # answer. A chat turn ends at :input_required rather than a terminal
        # status, so the claim is the only signal that covers both.
        return if workflow.status_terminal? || already_delivered?(workflow)

        adapter = resolve_adapter(callback_context)
        return unless adapter

        delta = ::Ai::DuoWorkflows::ProgressReader.new.delta_since(
          workflow, cursor: callback_context['progress_cursor']
        )
        return if delta.empty?

        # Only the external render is best-effort: a failed delivery is re-rendered
        # from the same cursor on the next checkpoint (terminal delivery is the
        # must-not-lose backstop), so swallow it and don't advance the cursor. DB
        # errors propagate so Sidekiq retries instead of masking infra failures.
        begin
          adapter.on_progress(delta: delta, callback_context: callback_context, workflow: workflow)
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
          return
        end

        persist_progress_cursor(workflow, delta.cursor)
      end

      private

      def already_delivered?(workflow)
        workflow.messaging_callback_context['delivered_at'].present?
      end

      def resolve_adapter(callback_context)
        klass = ::Ai::Messaging::AdapterRegistry[callback_context['adapter']]
        return unless klass

        klass.from_callback_context(callback_context)
      end

      # Not status_ts: writing back this job's copy could overwrite a newer value.
      def persist_progress_cursor(workflow, cursor)
        workflow.merge_messaging_callback_context!('progress_cursor' => cursor)
      end
    end
    # rubocop:enable Sidekiq/EnforceDatabaseHealthSignalDeferral
  end
end
