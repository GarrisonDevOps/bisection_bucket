# frozen_string_literal: true

module AuditEvents
  module Streaming
    # Single seam through which audit events are handed off for streaming
    # to external destinations.
    #
    # When NATS is available (Gitlab::Nats.enabled?) and the per-root-group
    # rollout flag is on, the event is published to NATS JetStream; any
    # publish failure falls back to the existing Sidekiq enqueue
    # (AuditEvents::AuditEventStreamingWorker), preserving at-least-once
    # delivery. Otherwise, the Sidekiq path is used directly, which also
    # covers Self-Managed instances without NATS configured.
    class EnqueueService
      include ::Gitlab::Utils::StrongMemoize

      # Aggressive publish timeout so NATS unavailability cannot hang the
      # (often request-thread) audit path: on timeout we fall back to Sidekiq.
      PUBLISH_TIMEOUT = 0.1 # seconds

      # Version of the NATS message envelope. Bump this only for a released
      # envelope change so consumers can branch to stay compatible across a
      # rolling deploy. The initial shipped envelope carries: id, event_name,
      # group_id, persisted, model_class, namespace_ancestor_ids,
      # project_namespace, published_at, and the serialized event.
      PAYLOAD_SCHEMA_VERSION = 1

      # @param audit_event [AuditEvents::GroupAuditEvent,
      #   AuditEvents::ProjectAuditEvent, AuditEvents::UserAuditEvent,
      #   AuditEvents::InstanceAuditEvent] the event to stream
      # @param event_name [String] audit event type
      # @param use_json [Boolean] when true, the serialized event is passed
      #   in the job payload instead of being fetched from the database
      # @param model_class [String, nil] class name used by the worker to
      #   locate the event when `use_json` is false
      def initialize(audit_event, event_name:, use_json: false, model_class: nil)
        @audit_event = audit_event
        @event_name = event_name
        @use_json = use_json
        @model_class = model_class
      end

      def execute
        ensure_stable_id!

        # Shadow mode: publish to NATS to put the consumer under real load, but
        # always keep delivering through Sidekiq so the customer is still served
        # by the live path and no event is lost (the consumer skips the actual
        # send). Overrides the normal either/or routing below.
        if shadow_mode?
          publish_to_nats_for_shadow if shadow_publish?
          return ::AuditEvents::AuditEventStreamingWorker.perform_async(*sidekiq_args)
        end

        return if streamed_via_nats?

        ::AuditEvents::AuditEventStreamingWorker.perform_async(*sidekiq_args)
      end

      # Stable, transport-independent ID for this event. Persisted events use
      # their database ID; stream-only events use a UUID minted once at
      # enqueue time and carried in the serialized payload. The same value is
      # observed by every destination and is suitable for message-level
      # deduplication (e.g. the NATS Nats-Msg-Id header).
      #
      # Database IDs are collision-free as dedup keys only because all
      # streaming-path audit event tables share `audit_events_id_seq`
      # (see db/post_migrate/20260603075738_use_audit_events_id_seq_for_scoped_audit_events.rb).
      # Splitting the sequences again would reintroduce silent dedup drops;
      # the 'database id uniqueness invariant' spec in enqueue_service_spec.rb
      # enforces this and must not be weakened without revisiting this scheme.
      def stable_id
        ensure_stable_id!

        audit_event.id.presence&.to_s || audit_event.stream_id
      end

      private

      attr_reader :audit_event, :event_name, :use_json, :model_class

      # Returns true only when the event was routed to NATS and the publish
      # was acknowledged. Returns false when NATS routing does not apply
      # (gates off) or the publish failed, so the caller falls back to the
      # Sidekiq path.
      def streamed_via_nats?
        return false unless use_nats?

        published, error = publish_to_nats
        track_publish_result(published, error)
        published
      rescue StandardError => e
        ::Gitlab::ErrorTracking.log_exception(e, event_name: event_name, fallback_reason: fallback_reason(e))
        track_publish_result(false, e)
        false
      end

      def ensure_stable_id!
        return if audit_event.id.present?

        audit_event.stream_id ||= SecureRandom.uuid
      end

      def shadow_mode?
        ::Gitlab::Nats.enabled? &&
          ::Feature.enabled?(:audit_event_streaming_nats_shadow_mode, :instance)
      end

      # Shadow publish is gated separately from the consumer's shadow drain so
      # publishing can be stopped while the consumer keeps draining and
      # discarding the backlog, clearing the stream with no delivery to
      # customers before shadow mode itself is turned off.
      def shadow_publish?
        ::Feature.enabled?(:audit_event_streaming_nats_shadow_publish, :instance)
      end

      # Best-effort publish so the consumer gets real load; failures must never
      # block the Sidekiq path that actually delivers the event in shadow mode.
      # Records the same publish/fallback metrics as the live path so the
      # dashboards preview how NATS would perform once it is the real transport.
      def publish_to_nats_for_shadow
        published, error = publish_to_nats
        track_publish_result(published, error)
      rescue StandardError => e
        ::Gitlab::ErrorTracking.log_exception(e, event_name: event_name, fallback_reason: fallback_reason(e))
        track_publish_result(false, e)
      end

      # Layered routing:
      # 1. Gitlab::Nats.enabled? - capability (connection settings present)
      #    plus the operator-controlled application setting.
      # 2. audit_event_streaming_via_nats - short-lived per-root-group
      #    rollout flag; to be removed once the rollout completes, leaving
      #    Gitlab::Nats.enabled? as the sole gate.
      def use_nats?
        return false unless ::Gitlab::Nats.enabled?

        root_group = audit_event.root_group_entity

        if root_group
          ::Feature.enabled?(:audit_event_streaming_via_nats, root_group)
        else
          # Instance-scoped events have no root group actor.
          ::Feature.enabled?(:audit_event_streaming_via_nats, :instance) # -- instance-scoped events have no group actor
        end
      end

      # Publishes and reports the outcome. Any failure is logged and reported
      # so the caller falls back to the Sidekiq path (at-least-once delivery is
      # preserved; consumers deduplicate via the stable event ID).
      #
      # @return [Array(Boolean, StandardError, nil)] whether the server
      #   acknowledged, and the failure (nil on success) for reason
      #   classification.
      def publish_to_nats
        started = ::Gitlab::Metrics::System.monotonic_time
        subject = nats_subject

        ::Gitlab::Nats.client.publish(
          subject,
          nats_payload,
          message_id: stable_id,
          timeout: PUBLISH_TIMEOUT
        )

        [true, nil]
      rescue StandardError => e
        ::Gitlab::ErrorTracking.log_exception(
          e,
          event_name: event_name,
          subject: subject,
          fallback_reason: fallback_reason(e)
        )

        [false, e]
      ensure
        # In ensure so we capture the time the caller's thread was blocked on
        # every path (ack, fallback, or timeout).
        ::Gitlab::Metrics::AuditEventStreamingSlis.record_publish_duration(
          ::Gitlab::Metrics::System.monotonic_time - started
        )
      end

      def nats_subject
        ::AuditEvents::Streaming::NatsPartitioning.subject_for(root_group_id)
      end

      def root_group_id
        audit_event.root_group_entity&.id
      end

      def nats_payload
        ::Gitlab::Json.generate({
          schema_version: PAYLOAD_SCHEMA_VERSION,
          id: stable_id,
          event_name: event_name,
          group_id: root_group_id,
          persisted: audit_event.id.present?,
          model_class: model_class,
          namespace_ancestor_ids: namespace_ancestor_ids,
          project_namespace: project_namespace?,
          # Explicit UTC ISO8601 (with the trailing Z). The consumer parses
          # and compares in UTC too, so consumer-lag is an unambiguous instant
          # difference independent of the app or host time zone.
          published_at: Time.current.utc.iso8601(3),
          event: audit_event.as_json
        })
      end

      # Self-and-ancestor namespace IDs for the event's streamable namespace,
      # captured at publish time so the batched consumer can evaluate
      # namespace filters (a set intersection) without reconstructing the
      # event object and hitting Postgres on the hot path. Empty when the
      # event has no streamable namespace (namespace filters then do not
      # restrict it).
      def namespace_ancestor_ids
        namespace = streamable_namespace
        return [] unless namespace

        namespace.self_and_ancestor_ids
      end

      def project_namespace?
        streamable_namespace.is_a?(::Namespaces::ProjectNamespace)
      end

      def streamable_namespace
        return unless audit_event.respond_to?(:streamable_namespace)

        audit_event.streamable_namespace
      end
      strong_memoize_attr :streamable_namespace

      def track_publish_result(published, error = nil)
        ::Gitlab::Metrics::AuditEventStreamingSlis.record_publish(
          fallback: !published,
          reason: (fallback_reason(error) if error)
        )
      end

      # Classifies a publish failure into a bounded reason for the fallback
      # metric (never the raw class/message, to keep counter cardinality fixed).
      #
      # @param error [StandardError]
      # @return [Symbol] one of Gitlab::Metrics::AuditEventStreamingSlis::FALLBACK_REASONS
      def fallback_reason(error)
        case error
        when ::NATS::IO::Timeout then :timeout
        when ::Gitlab::Nats::Client::ConnectionError then :connection_lost
        when ::NATS::JetStream::Error then :server_error
        else :unexpected
        end
      end

      def sidekiq_args
        return [event_name, nil, streaming_json] if use_json

        args = [event_name, audit_event.id, nil]
        args << model_class if model_class
        args
      end

      def streaming_json
        ::Gitlab::Json.generate(audit_event, methods: [:root_group_entity_id, :stream_id])
      end
    end
  end
end
