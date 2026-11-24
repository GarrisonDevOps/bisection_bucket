# frozen_string_literal: true

module AuditEvents
  class AiAuditEventStreamingWorker
    include ApplicationWorker
    include ::Gitlab::InternalEventsTracking

    # AI audit events contain a `cloud_event_id` UUID; ingesting systems should
    # deduplicate based on that to make this job safely retryable.
    idempotent!
    worker_has_external_dependencies!
    data_consistency :sticky
    feature_category :audit_events
    sidekiq_options retry: 3

    STREAMING_COUNTER = Gitlab::Metrics.counter(
      :gitlab_ai_audit_events_streaming_total,
      'AI audit events processed by streaming worker'
    )

    def perform(audit_event_json)
      return if ::Gitlab::SilentMode.enabled?

      ai_audit_event = build_audit_event(audit_event_json)
      return if ai_audit_event.nil?

      streamer = ::AuditEvents::ExternalDestinationStreamer.new(ai_audit_event.event_name, ai_audit_event)
      streamable = streamer.streamable?

      begin
        streamer.stream_to_destinations
        STREAMING_COUNTER.increment(streamable: streamable, status: :success)
        track_streamed_event(ai_audit_event) if streamable
      rescue StandardError
        STREAMING_COUNTER.increment(streamable: streamable, status: :error)
        raise
      end
    end

    private

    def track_streamed_event(ai_audit_event)
      root_group = ai_audit_event.root_group_entity
      return unless root_group

      entity = ai_audit_event.entity

      track_internal_event(
        'stream_ai_audit_event_to_external_destination',
        project: entity.is_a?(::Project) ? entity : nil,
        namespace: root_group
      )
    end

    def build_audit_event(audit_event_json)
      payload = ::Gitlab::Json.safe_parse(audit_event_json).with_indifferent_access

      attrs = payload.slice(*::AuditEvents::AiAuditEvent::STREAMABLE_ATTRIBUTES)
      ai_audit_event = ::AuditEvents::AiAuditEvent.new(attrs)
      ai_audit_event.root_group_entity_id = payload[:root_group_entity_id]
      # Override the rebuilt record's `id` to return `cloud_event_id` so
      # `AuditEvents::Streaming::Destinations::BaseStreamDestination#request_body`
      # does not synthesise a fresh `SecureRandom.uuid` on every retry. A
      # singleton method bypasses AR's integer type-casting of the bigserial
      # primary key column. The record is in-memory only and never saved, so
      # this override has no persistence side-effects.
      ai_audit_event.define_singleton_method(:id) { ai_audit_event.cloud_event_id }
      ai_audit_event
    rescue JSON::ParserError => e
      ::Gitlab::ErrorTracking.track_exception(e)
      nil
    end
  end
end
