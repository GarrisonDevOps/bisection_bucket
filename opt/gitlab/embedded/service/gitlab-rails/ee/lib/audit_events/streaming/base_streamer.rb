# frozen_string_literal: true

module AuditEvents
  module Streaming
    class BaseStreamer
      include Gitlab::InternalEventsTracking
      include Gitlab::Utils::StrongMemoize

      INTERNAL_EVENTS = %w[delete_epic delete_issue delete_merge_request delete_work_item].freeze
      STREAMABLE_NOT_IMPLEMENTED_MESSAGE = 'Subclasses must implement the `streamable?` method'
      DESTINATIONS_NOT_IMPLEMENTED_MESSAGE = 'Subclasses must implement the `destinations` method'

      attr_reader :event_type, :audit_event

      def initialize(event_type, audit_event)
        @event_type = event_type
        @audit_event = audit_event
      end

      def streamable?
        raise NotImplementedError, _(STREAMABLE_NOT_IMPLEMENTED_MESSAGE)
      end

      def execute
        return unless streamable?

        eligible_destinations = AuditEvents::Streaming::CircuitBreaker.reject_open(
          destinations.to_a, delivery_mode: :per_event, event_count: 1
        )

        eligible_destinations.each do |destination|
          track_and_stream(destination) if destination.allowed_to_stream?(event_type, audit_event)
        end
      end

      private

      def destinations
        raise NotImplementedError, _(DESTINATIONS_NOT_IMPLEMENTED_MESSAGE)
      end

      def track_and_stream(destination)
        track_audit_event
        outcome = stream_to_destination(destination)
        log_slow_or_rejected_delivery(destination, outcome)

        if outcome.delivered?
          log_streaming_success(destination, outcome)
          AuditEvents::Streaming::CircuitBreaker.record_success(destination)
        else
          handle_failure(destination, outcome.error, outcome.error_category)
        end
      rescue StandardError => e
        handle_failure(destination, e, :internal_error)
      end

      def handle_failure(destination, error, error_category)
        context = {
          audit_event_id: audit_event_id,
          destination_id: destination.id,
          destination_name: destination.name,
          destination_category: destination.category,
          error_category: error_category
        }

        if error_category == :internal_error
          Gitlab::ErrorTracking.track_exception(error, context)
        else
          Gitlab::ErrorTracking.log_exception(error, context)
          AuditEvents::Streaming::CircuitBreaker.record_failure(destination)
        end
      end

      # For an FF-enabled group the NATS path delivers a JSON array, so a
      # Sidekiq fallback must use the same schema; the customer cannot tell
      # which path a given event took.
      def stream_to_destination(destination)
        stream_destination_class = AuditEvents::Streaming::Destinations.for_category(destination.category)

        stream_destination_class.new(event_type, audit_event, destination).deliver(batch_schema: batch_schema?)
      end

      def batch_schema?
        return false unless ::Gitlab::Nats.enabled?

        ::Feature.enabled?(:audit_event_streaming_via_nats, audit_event.root_group_entity || :instance)
      end
      strong_memoize_attr :batch_schema?

      def log_slow_or_rejected_delivery(destination, outcome)
        return unless outcome.slow_or_rejected?

        Gitlab::AppLogger.info(
          delivery_log_fields(destination, outcome).merge(
            message: 'Audit event delivery slow or rejected',
            Labkit::Fields::GL_ROOT_NAMESPACE_ID => audit_event.root_group_entity&.id,
            Labkit::Fields::DURATION_S => outcome.logged_duration_s,
            error_category: outcome.error_category
          )
        )
      end

      def log_streaming_success(destination, outcome)
        Gitlab::AppLogger.debug(
          delivery_log_fields(destination, outcome).merge(
            message: 'Audit event streamed',
            destination_name: destination.name,
            event_type: event_type
          )
        )
      end

      def delivery_log_fields(destination, outcome)
        {
          audit_event_id: audit_event_id,
          destination_id: destination.id,
          destination_category: destination.category,
          Labkit::Fields::HTTP_STATUS_CODE => outcome.status_code
        }
      end

      # Stream-only events have no database id, so fall back to the stream id
      # that destinations receive. Stringified to keep the log field one type.
      def audit_event_id
        (audit_event.id.presence || audit_event.try(:stream_id))&.to_s
      end

      def track_audit_event
        return unless event_type.in?(INTERNAL_EVENTS)

        track_internal_event("trigger_audit_event", additional_properties: { label: event_type })
      end
    end
  end
end
