# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Destinations
      class BaseStreamDestination
        REQUEST_BODY_SIZE_LIMIT = 25.megabytes
        STREAM_ERROR_MESSAGE = 'Subclasses must implement the `stream` method'
        EVENT_TYPE_HEADER_KEY = "X-Gitlab-Audit-Event-Type"

        # :internal_error is a GitLab-side bug and goes to Sentry; every other category
        # is destination-side, so it is logged and trips the circuit breaker.
        # :invalid_config means the destination cannot be used as configured
        # (unparseable URL or key, blocked host, redirect loop, bucket in another
        # region) and only a settings change fixes it; :auth and :not_found are
        # rejections of a well-formed request, kept apart so a fleet-wide spike
        # in rejections after a deploy points at us while invalid_config stays
        # one customer's broken setup.
        ERROR_CATEGORIES = %i[
          timeout connection auth not_found rate_limited client_error server_error invalid_config internal_error
        ].freeze

        # Ordered, first match wins. The HTTP client's catch-all list goes last
        # so the specific entries above it take precedence.
        TRANSPORT_ERROR_CATEGORIES = [
          [URI::InvalidURIError, :invalid_config],
          [JSON::ParserError, :invalid_config],
          [Gitlab::HTTP::BlockedUrlError, :invalid_config],
          [Gitlab::HTTP::RedirectionTooDeep, :invalid_config],
          [Gitlab::HTTP_V2::HeaderInjectionError, :invalid_config],
          *Gitlab::HTTP::HTTP_TIMEOUT_ERRORS.map { |klass| [klass, :timeout] },
          [Errno::ETIMEDOUT, :timeout],
          *Gitlab::HTTP::HTTP_ERRORS.map { |klass| [klass, :connection] }
        ].freeze

        attr_reader :event_type, :audit_event, :destination

        # event_type/audit_event are per-event and do not apply to a batch.
        def self.for_batch(destination)
          new(nil, nil, destination)
        end

        def initialize(event_type, audit_event, destination)
          @event_type = event_type
          @audit_event = audit_event
          @destination = destination
        end

        # Delivers one event and never raises: the outcome carries the error
        # and its category so every caller logs, reports and trips the circuit
        # breaker the same way.
        def deliver(batch_schema: false)
          with_outcome(1) { batch_schema ? stream_as_batch : stream }
        end

        def deliver_batch(event_bodies)
          with_outcome(event_bodies.size) { stream_batch(event_bodies) }
        end

        def stream
          raise NotImplementedError, _(STREAM_ERROR_MESSAGE)
        end

        # @param event_bodies [Array<Hash>] serialized event bodies, each
        #   self-describing (`id`, `event_type`, and event fields).
        def stream_batch(event_bodies)
          raise NotImplementedError, _(STREAM_ERROR_MESSAGE)
        end

        # Streams a single per-event instance using the batch (JSON array)
        # schema, so a Sidekiq fallback for an FF-enabled group is identical to
        # the NATS batch path: a one-element array, and no per-request
        # X-Gitlab-Audit-Event-Type header (the type is carried per-element in
        # the body). Delegating through for_batch clears @event_type so the
        # header is omitted, matching the NATS path exactly.
        def stream_as_batch
          body = event_body_hash
          # The NATS path sends a string id (stable_id); stringify here so a
          # persisted event's integer id matches that shape on the fallback.
          body["id"] = body["id"].to_s

          self.class.for_batch(@destination).stream_batch([body])
        end

        protected

        def encode_body(body)
          Gitlab::Json::LimitedEncoder.encode(body, limit: REQUEST_BODY_SIZE_LIMIT)
        end

        # Gitlab::HTTP only raises for transport failures; a 4xx/5xx comes
        # back as a plain response and would otherwise count as delivered.
        def ensure_success(response)
          return response if response.success? || !fail_on_non_2xx_response?

          raise DestinationError, response.code
        end

        def request_body
          encode_body(event_body_hash)
        end

        def event_body_hash
          raise ArgumentError, 'requires a per-event instance; use stream_batch for batch-mode' if
            @audit_event.nil?

          body = @audit_event.as_json
          body[:event_type] = @event_type
          # Stream-only events have a blank database id. Prefer the upstream
          # `stream_id` so every destination and transport sees the same ID
          # (customer-side deduplication); fall back to a UUID for events
          # enqueued before `stream_id` existed.
          body["id"] = upstream_stream_id || SecureRandom.uuid if @audit_event.id.blank?
          body
        end

        def upstream_stream_id
          # AuditEvents::AiAuditEvent reaches this layer without
          # CommonAuditEventStreamable (it dedups by `cloud_event_id`), so it
          # has no `stream_id`. Guard removable once all event classes define it.
          return unless @audit_event.respond_to?(:stream_id)

          @audit_event.stream_id.presence
        end

        private

        def with_outcome(count)
          started_at = Gitlab::Metrics::System.monotonic_time
          outcome = begin
            Outcome.new(response: yield)
          rescue StandardError => e
            Outcome.new(error: e, error_category: known_error_category(classify_error(e)))
          end

          outcome.duration_s = Gitlab::Metrics::System.monotonic_time - started_at

          record_delivery(outcome, count)
          outcome
        rescue StandardError => e
          # No outcome yet means classification itself failed; hand the error to
          # the caller, which reports it with destination context.
          return record_unclassified_failure(e, count) unless outcome

          Gitlab::ErrorTracking.track_exception(e)
          outcome
        end

        def record_unclassified_failure(error, count)
          outcome = Outcome.new(error: error, error_category: :internal_error)
          record_delivery(outcome, count)
          outcome
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e)
          outcome
        end

        # A category outside the fixed set would otherwise read as destination-side
        # and skip Sentry, so an unknown one is treated as our bug.
        def known_error_category(error_category)
          ERROR_CATEGORIES.include?(error_category) ? error_category : :internal_error
        end

        # Subclasses map their own client's exceptions first and fall back here.
        def classify_error(error)
          return :connection if dns_lookup_failure?(error)
          return status_error_category(error.status) || :server_error if error.is_a?(DestinationError)

          TRANSPORT_ERROR_CATEGORIES.find { |klass, _| error.is_a?(klass) }&.last || :internal_error
        end

        # The URL blocker raises BlockedUrlError when a DNS lookup fails or times
        # out, which can be temporary. It raises inside the rescue, so the
        # original error is kept as the cause.
        def dns_lookup_failure?(error)
          return false unless error.is_a?(Gitlab::HTTP::BlockedUrlError)

          cause = error.cause
          cause = cause.cause while cause.is_a?(Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError)
          cause.is_a?(SocketError) || cause.is_a?(Timeout::Error)
        end

        def status_error_category(status)
          case status
          when 401, 403 then :auth
          when 404 then :not_found
          when 408 then :timeout
          when 425, 429 then :rate_limited
          when 300..399 then :invalid_config
          when 400..499 then :client_error
          when 500..599 then :server_error
          end
        end

        def fail_on_non_2xx_response?
          ::Feature.enabled?(:audit_event_streaming_fail_on_non_2xx_response, feature_flag_actor)
        end

        # Group destinations belong to a top-level group; instance destinations
        # have none. actor_from_id skips loading the group for the flag check.
        def feature_flag_actor
          group_id = destination.try(:group_id)
          group_id ? ::Group.actor_from_id(group_id) : :instance
        end

        def record_delivery(outcome, count)
          category = destination.category
          delivery_outcome = delivery_outcome(outcome)

          Gitlab::Metrics::AuditEventStreamingSlis.record_delivery(
            category: category,
            outcome: delivery_outcome,
            error_category: outcome.error_category || :none,
            count: count
          )
          Gitlab::Metrics::AuditEventStreamingSlis.observe_delivery_duration(
            category: category,
            outcome: delivery_outcome,
            seconds: outcome.duration_s
          )
        end

        def delivery_outcome(outcome)
          return :success if outcome.delivered?
          return :internal_error if outcome.internal_error?

          :destination_error
        end
      end
    end
  end
end
