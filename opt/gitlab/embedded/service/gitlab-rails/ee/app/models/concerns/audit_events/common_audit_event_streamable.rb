# frozen_string_literal: true

module AuditEvents
  module CommonAuditEventStreamable
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    # Stable streaming ID for events that are not persisted (no database
    # `id`). Assigned once at enqueue time (AuditEvents::Streaming::EnqueueService)
    # and carried through the serialized payload so every destination and
    # transport (Sidekiq or NATS) observes the same ID, enabling
    # customer-side deduplication.
    attr_accessor :stream_id

    def stream_to_external_destinations(use_json: false, event_name: 'audit_operation')
      return unless can_stream_to_external_destination?(event_name)

      # Set at enqueue: log lines read root_namespace from the job payload snapshot, not from context during perform.
      ::Gitlab::ApplicationContext.with_context(namespace: streamable_namespace) do
        ::AuditEvents::Streaming::EnqueueService.new(
          self,
          event_name: event_name,
          use_json: use_json,
          model_class: self.class.name
        ).execute
      end
    end

    private

    def can_stream_to_external_destination?(event_name)
      return false if ::Gitlab::SilentMode.enabled?
      return false if entity.nil?

      ::AuditEvents::ExternalDestinationStreamer.new(event_name, self).streamable?
    end
  end
end
