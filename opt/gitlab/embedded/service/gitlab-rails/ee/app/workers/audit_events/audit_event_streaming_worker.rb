# frozen_string_literal: true

module AuditEvents
  class AuditEventStreamingWorker
    include ApplicationWorker

    # Audit events contains a unique ID so the ingesting system should
    # attempt to deduplicate based on this to allow this job to be idempotent.
    idempotent!
    worker_has_external_dependencies!
    data_consistency :sticky
    feature_category :audit_events
    loggable_arguments 0, 1
    sidekiq_options retry: 3

    STREAMING_COUNTER = Gitlab::Metrics.counter(
      :gitlab_audit_event_streaming_worker_total,
      'Audit events processed by streaming worker'
    )

    CIRCUIT_BREAKER_COUNTER = Gitlab::Metrics.counter(
      :gitlab_audit_event_streaming_circuit_breaker_total,
      'Audit event streaming destinations tripped open by the circuit breaker'
    )

    def perform(audit_operation, audit_event_id, audit_event_json = nil, model_class = nil)
      return if ::Gitlab::SilentMode.enabled?

      raise ArgumentError, 'audit_event_id and audit_event_json cannot be passed together' if audit_event_id.present? && audit_event_json.present?

      audit_event = ::AuditEvents::Processor.fetch(
        audit_event_id: audit_event_id,
        audit_event_json: audit_event_json,
        model_class: model_class
      )

      if audit_event.nil?
        log_extra_metadata_on_done(:error, "Failed to fetch audit event")
        return
      end

      definition = ::Gitlab::Audit::Type::Definition.get(audit_operation)
      streamer = AuditEvents::ExternalDestinationStreamer.new(audit_operation, audit_event)

      STREAMING_COUNTER.increment(
        should_stream: definition&.streamed || false,
        should_persist: definition&.saved_to_database || false,
        streamable: streamer.streamable?
      )

      streamer.stream_to_destinations

      log_extra_metadata_on_done(:audit_event_type, audit_operation)
      log_extra_metadata_on_done(:namespace_id, audit_event.root_group_entity&.id)
    end
  end
end
