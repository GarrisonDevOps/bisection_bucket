# frozen_string_literal: true

module Ai
  module Messaging
    module Adapters
      # Delivers Duo flow lifecycle events to an existing project or group webhook
      # that has `duo_flow_callback_enabled` set, so an external client can be
      # pushed updates instead of polling. Selected via
      # messaging_callback_context['adapter'] == 'webhook', set by
      # API::Ai::DuoWorkflows::Workflows when the request carries a
      # `callback_hook_id`.
      #
      # Never constructed via Base#trigger: flows using this adapter come from the
      # create-flow API, so CallbackWorker and ProgressDeliveryWorker drive every
      # live delivery.
      class Webhook < Base
        include ::Ai::Messaging::UiChatLog

        EVENT_STARTED = 'flow.started'
        EVENT_PROGRESS = 'flow.progress'
        EVENT_COMPLETED = 'flow.completed'
        EVENT_FAILED = 'flow.failed'

        OBJECT_KIND = 'duo_workflow'
        PAYLOAD_VERSION = '1'
        EVENT_ID_NAMESPACE = 'gitlab-duo-flow-callback-hook'

        # The plan and activity re-ship in full on every progress frame and come from
        # model-generated content, so they are capped to keep the payload bounded.
        ACTIVITY_MAX_LENGTH = 1500
        PLAN_MAX_TODOS = 20
        PLAN_DESCRIPTION_MAX_LENGTH = 200

        def self.adapter_key
          'webhook'
        end

        def self.supports_live_progress?
          true
        end

        def self.workflow_attributes(workflow)
          return unless workflow

          {
            'id' => workflow.id,
            'status' => workflow.status_name.to_s,
            'web_url' => workflow.web_url
          }.compact
        end

        def self.from_callback_context(ctx)
          new(hook_id: ctx['hook_id'], client_reference: ctx['client_reference'])
        end

        def initialize(hook_id:, client_reference: nil)
          @hook_id = hook_id
          @client_reference = client_reference
        end

        def build_callback_context
          {
            'adapter' => self.class.adapter_key,
            'hook_id' => @hook_id,
            'client_reference' => @client_reference
          }.compact
        end

        def on_flow_started(callback_context:, workflow:) # rubocop:disable Lint/UnusedMethodArgument -- kwarg name fixed by the Base contract
          enqueue(event: EVENT_STARTED, workflow: workflow)
        end

        def deliver_result(callback_context:, message:, workflow:) # rubocop:disable Lint/UnusedMethodArgument -- kwarg name fixed by the Base contract
          enqueue(event: EVENT_COMPLETED, workflow: workflow, result: { 'message' => message })
        end

        def on_flow_completed(callback_context:, workflow:); end

        # Overrides Base#on_flow_failed (which would drop the workflow and call
        # deliver_error) so failures keep workflow context in the payload.
        def on_flow_failed(callback_context:, error:, workflow: nil) # rubocop:disable Lint/UnusedMethodArgument -- kwarg name fixed by the Base contract
          enqueue(event: EVENT_FAILED, workflow: workflow, error: error)
        end

        # Sync-failure fallback (no workflow yet). Not reachable on this adapter's
        # only trigger path, but implemented to satisfy the Base contract.
        def deliver_error(callback_context:, error:) # rubocop:disable Lint/UnusedMethodArgument -- kwarg name fixed by the Base contract
          enqueue(event: EVENT_FAILED, workflow: nil, error: error)
        end

        # Best-effort: async_execute applies the webhook rate limit and never redelivers a
        # rejected frame, because the next one carries the full state. project and user
        # came with flow.started, so a frame leaves them out.
        def on_progress(delta:, callback_context:, workflow:) # rubocop:disable Lint/UnusedMethodArgument -- kwarg name fixed by the Base contract
          return unless delta.new_messages.any? { |message| renders_progress?(message) }

          hook = find_hook
          return unless hook

          payload = base_payload(
            event: EVENT_PROGRESS,
            event_id: SecureRandom.uuid,
            plan: progress_plan(delta.messages).presence,
            activity: latest_agent_content(delta.messages)&.truncate(ACTIVITY_MAX_LENGTH, separator: ' ')
          ).merge('workflow' => self.class.workflow_attributes(workflow)).compact

          hook.async_execute(
            payload, ::Ai::Messaging::WebhookDeliveryWorker::HOOK_NAME, idempotency_key: payload['event_id']
          )
        end

        private

        def enqueue(event:, workflow:, result: nil, error: nil)
          return if @hook_id.blank?
          # A silent instance sends nothing, so do not queue a job that can only drop.
          return if ::Gitlab::SilentMode.enabled?
          return unless find_hook

          payload = base_payload(
            event: event, event_id: event_id(event, workflow), result: result, error: error_attributes(error)
          )

          ::Ai::Messaging::WebhookDeliveryWorker.perform_async(@hook_id, workflow&.id, payload)
        end

        def base_payload(event:, event_id:, **attributes)
          {
            'object_kind' => OBJECT_KIND,
            'version' => PAYLOAD_VERSION,
            'event' => event,
            'event_id' => event_id,
            'client_reference' => @client_reference
          }.merge(attributes.stringify_keys).compact
        end

        def progress_plan(messages)
          latest_todos(messages).first(PLAN_MAX_TODOS).map do |todo|
            {
              'description' => todo['description'].to_s.truncate(PLAN_DESCRIPTION_MAX_LENGTH, separator: ' '),
              'status' => todo['status'].to_s
            }
          end
        end

        # Eligibility is settled at trigger time; this only honours an owner unticking
        # the hook. The column is on the shared web_hooks table, hence the type check.
        def find_hook
          hook = ::WebHook.find_by_id(@hook_id)
          return unless hook&.duo_flow_callback_enabled?
          return unless hook.is_a?(::ProjectHook) || hook.is_a?(::GroupHook)

          hook
        end

        def error_attributes(error)
          return if error.blank?

          attrs = { 'reason' => error.to_s }
          attrs['message'] = error.message if error.respond_to?(:message)
          attrs
        end

        # Deterministic per (workflow, event, hook) so an at-least-once redelivery dedupes.
        # With no workflow nothing identifies the event, so a random id avoids collisions.
        def event_id(event, workflow)
          return SecureRandom.uuid unless workflow

          ::Gitlab::UUID.v5([EVENT_ID_NAMESPACE, workflow.id, event, @hook_id].join(':'))
        end
      end
    end
  end
end
