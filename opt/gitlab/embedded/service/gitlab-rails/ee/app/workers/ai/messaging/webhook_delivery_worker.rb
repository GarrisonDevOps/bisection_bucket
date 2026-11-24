# frozen_string_literal: true

module Ai
  module Messaging
    # Delivers one Duo flow lifecycle event (Ai::Messaging::Adapters::Webhook) to
    # a project or group webhook via WebHookService.
    #
    # Not WebHook#async_execute: that path swallows HTTP failures and never
    # redelivers, so a dropped flow.completed would leave a client waiting forever.
    # Delivery runs here and raises on anything the receiver rejected, so Sidekiq
    # retries with backoff.
    class WebhookDeliveryWorker
      include ApplicationWorker

      DeliveryError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

      HOOK_NAME = 'duo_flow_callback'
      MAX_DISABLED_REQUEUES = 3

      REQUIRED_PAYLOAD_KEYS = %w[object_kind version event event_id].freeze

      feature_category :duo_agent_platform
      data_consistency :delayed
      urgency :low
      # dead: false keeps a persistently unreachable endpoint out of the dead set.
      sidekiq_options retry: 5, dead: false
      defer_on_database_health_signal :gitlab_main, [:web_hook_logs], 1.minute
      idempotent!
      worker_has_external_dependencies!

      sidekiq_retries_exhausted do |job, exception|
        hook_id, workflow_id, base_payload = job['args']

        log_dropped(
          hook_id: hook_id,
          workflow_id: workflow_id,
          payload: base_payload,
          reason: 'retries_exhausted',
          error_message: exception&.message
        )
      end

      def self.log_dropped(hook_id:, workflow_id:, payload:, reason:, error_message: nil)
        Gitlab::WebHooks::Logger.build.error({
          hook_id: hook_id,
          action: 'duo_flow_callback_dropped',
          Labkit::Fields::LOG_MESSAGE => reason,
          Labkit::Fields::GL_ORGANIZATION_ID => ::WebHook.find_by_id(hook_id)&.parent&.organization_id,
          Labkit::Fields::DUO_WORKFLOW_ID => workflow_id,
          event: payload&.dig('event'),
          event_id: payload&.dig('event_id'),
          Labkit::Fields::ERROR_MESSAGE => error_message
        }.compact)
      end

      def perform(hook_id, workflow_id, base_payload, requeue_count = 0)
        return unless payload_complete?(base_payload, hook_id)
        return if dropped_in_silent_mode?(hook_id, workflow_id, base_payload)

        hook = ::WebHook.find_by_id(hook_id)
        # Re-checked here so unticking a hook also stops queued and retried deliveries.
        return unless hook&.duo_flow_callback_enabled?
        return if deferred_while_disabled?(hook, workflow_id, base_payload, requeue_count)

        payload = build_payload(base_payload, workflow_id)

        response = ::WebHookService.new(
          hook, payload, HOOK_NAME, idempotency_key: base_payload['event_id']
        ).execute

        return if delivered?(response)

        raise DeliveryError, "Duo flow callback delivery failed: #{response.message}"
      end

      private

      def payload_complete?(base_payload, hook_id)
        missing = REQUIRED_PAYLOAD_KEYS.reject { |key| base_payload[key].present? }
        return true if missing.empty?

        Gitlab::AppLogger.warn(
          message: 'Duo flow callback: dropped a delivery with an incomplete payload',
          missing_keys: missing,
          hook_id: hook_id
        )

        false
      end

      def build_payload(base_payload, workflow_id)
        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id) if workflow_id

        base_payload.merge(
          'project' => workflow&.project&.hook_attrs&.deep_stringify_keys,
          'user' => workflow&.user&.hook_attrs&.deep_stringify_keys,
          'workflow' => ::Ai::Messaging::Adapters::Webhook.workflow_attributes(workflow)
        ).compact
      end

      def delivered?(response)
        response.success? && response.payload[:response_category] == :ok
      end

      # Silent mode stops all outbound traffic and no retry will change that, so treat
      # it as a drop, the way every other worker and WebHookService#async_execute do.
      def dropped_in_silent_mode?(hook_id, workflow_id, base_payload)
        return false unless ::Gitlab::SilentMode.enabled?

        self.class.log_dropped(
          hook_id: hook_id, workflow_id: workflow_id, payload: base_payload, reason: 'silent_mode'
        )

        true
      end

      # WebHookService returns 'Hook disabled' without writing a WebHookLog row, so
      # retrying inside the window would burn the retry budget and leave no trace.
      def deferred_while_disabled?(hook, workflow_id, base_payload, requeue_count)
        return false if hook.executable?

        if hook.permanently_disabled? || requeue_count >= MAX_DISABLED_REQUEUES
          self.class.log_dropped(
            hook_id: hook.id,
            workflow_id: workflow_id,
            payload: base_payload,
            reason: hook.permanently_disabled? ? 'hook_disabled' : 'wait_exhausted'
          )
        else
          self.class.perform_at(resume_at(hook), hook.id, workflow_id, base_payload, requeue_count + 1)
        end

        true
      end

      # A hook can be temporarily disabled with no disabled_until set, so fall back
      # to the shortest window the model would ever apply.
      def resume_at(hook)
        hook.disabled_until || ::WebHooks::AutoDisabling::INITIAL_BACKOFF.from_now
      end
    end
  end
end
