# frozen_string_literal: true

module AuditEvents
  module Streaming
    # Dispatches a batch of audit events for one top-level group to that
    # group's active external streaming destinations as batched payloads.
    #
    # This is where the pgbouncer reduction comes from: destination config is
    # looked up once per (group x batch) and payloads come from the NATS
    # message body, not a per-event Postgres fetch. A batch may mix event
    # types and namespaces, so events are still filtered per destination
    # (event-type and namespace filters) before the survivors are bundled
    # into one request.
    class BatchedDispatcher
      include ::Gitlab::Utils::StrongMemoize

      MAX_DESTINATIONS = ::AuditEvents::ExternallyStreamable::MAXIMUM_DESTINATIONS_PER_ENTITY
      PermanentFailure = Struct.new(:destination, :outcome, :event_count)
      # Stand-in for a destination round trip in shadow mode, so the drain
      # exercises realistic per-batch timing without a real network call.
      SHADOW_LATENCY = 0.05 # seconds
      # Failures that a retry cannot fix (bad config or credentials, 401/403,
      # 404, other 4xx). Redelivering them only resends the batch to the
      # group's other destinations, so they are recorded and not retried.
      PERMANENT_ERROR_CATEGORIES = %i[invalid_config auth not_found client_error].freeze

      # @param group_id [Integer, nil] top-level group ID; nil for
      #   instance-scoped events (only instance destinations apply)
      # @param payloads [Array<Hash>] parsed NATS message payloads for this
      #   group (schema v1 envelope: id, event_name, namespace_ancestor_ids,
      #   project_namespace, event, ...)
      def initialize(group_id, payloads)
        @group_id = group_id
        @payloads = payloads
      end

      # Dispatches to every eligible destination and reports the aggregate
      # outcome, so the caller acks only on full delivery and classifies the
      # error-budget signal correctly.
      #
      # A failure caused solely by a destination-side / user-config error
      # (any outcome category other than :internal_error, e.g. Errno::ECONNRESET)
      # is reported as :destination_error rather than :failed: it is not a
      # GitLab-side fault, so it should not burn the dispatch error budget. It
      # still leaves the batch unacked so JetStream redelivers (at-least-once;
      # deduped downstream by event id), unless the error is in
      # PERMANENT_ERROR_CATEGORIES and
      # audit_event_streaming_nats_skip_permanent_failure_redelivery is on.
      #
      # @return [Symbol] :delivered when every destination succeeded or failed
      #   permanently (or there was nothing to send); :destination_error when
      #   a destination-side failure should be retried; :failed when any
      #   GitLab-side error occurred. Permanent failures are logged with the
      #   batch's real redeliver value, and counted as dropped only when acked.
      def execute
        return :delivered if destinations.empty?

        # Sequential dispatch (parallelism comes from concurrent partition
        # drainers, not threads here). map, not short-circuit, so a failing
        # destination does not stop the rest.
        outcomes = destinations.map { |destination| dispatch_to_destination(destination) }
        result = aggregate(outcomes)

        # Reported only now: whether the batch is redelivered depends on every
        # destination, and dropped events must be counted once, when acked.
        report_permanent_failures(redelivered: result != :delivered)

        result
      end

      private

      attr_reader :group_id, :payloads

      def aggregate(outcomes)
        return :failed if outcomes.include?(:failed)
        return :destination_error if outcomes.include?(:destination_error)

        :delivered
      end

      def permanent_failures
        @permanent_failures ||= []
      end

      def report_permanent_failures(redelivered:)
        permanent_failures.each do |failure|
          outcome = failure.outcome
          handle_dispatch_error(outcome.error, failure.destination, outcome.error_category,
            redeliver: redelivered, event_count: failure.event_count)
          next if redelivered

          ::Gitlab::Metrics::AuditEventStreamingSlis.record_permanent_failure(
            destination_category: failure.destination.category,
            error_category: outcome.error_category,
            event_count: failure.event_count
          )
        end
      end

      def destinations
        eligible = ::AuditEvents::Streaming::CircuitBreaker.reject_open(
          all_destinations, delivery_mode: :batched, event_count: payloads.size
        )
        eligible.select(&:active?)
      end
      strong_memoize_attr :destinations

      def all_destinations
        (group_destinations + instance_destinations)
      end

      def group_destinations
        group = ::Group.find_by_id(group_id)
        return [] unless group
        return [] unless group.licensed_feature_available?(:external_audit_events)

        group.external_audit_event_streaming_destinations.active.preload_filters.limit(MAX_DESTINATIONS).to_a
      end

      def instance_destinations
        return [] unless ::License.feature_available?(:external_audit_events)

        ::AuditEvents::Instance::ExternalStreamingDestination.active.preload_filters.limit(MAX_DESTINATIONS).to_a
      end

      # @return [Symbol] :ok when delivered or nothing was eligible;
      #   :permanent_failure when the failure is permanent and not retried;
      #   :destination_error when a destination-side failure should be
      #   retried; :failed otherwise.
      def dispatch_to_destination(destination)
        allowed = payloads.select { |payload| allowed_to_stream?(destination, payload) }
        return :ok if allowed.empty?

        stream_destination = batch_stream_destination_for(destination)
        bodies = allowed.map { |payload| event_body(payload) }

        if shadow_mode?
          # Do everything except the real delivery: the filtering and body
          # building above already ran, so shadow load matches live except for
          # the network call, which a short sleep stands in for. Do NOT touch
          # the circuit breaker here: it is keyed by destination and shared with
          # the live Sidekiq path, so recording a success for a delivery that
          # never happened would reset a real destination's failure state.
          sleep SHADOW_LATENCY
          return :ok
        end

        outcome = stream_destination.deliver_batch(bodies)
        log_slow_or_rejected_delivery(destination, outcome, bodies.size)

        if outcome.delivered?
          ::AuditEvents::Streaming::CircuitBreaker.record_success(destination)
          return :ok
        end

        handle_failed_delivery(outcome, destination, bodies.size)
      rescue StandardError => e
        handle_dispatch_error(e, destination, :internal_error)
        :failed
      end

      # A permanent failure is only collected here; report_permanent_failures
      # logs it once the batch's outcome is known.
      #
      # @return [Symbol] :failed for a GitLab-side error; :destination_error
      #   when the batch should be redelivered; :permanent_failure when the
      #   failure is permanent and redelivery is skipped.
      def handle_failed_delivery(outcome, destination, event_count)
        if !outcome.internal_error? && skip_redelivery?(outcome.error_category)
          permanent_failures << PermanentFailure.new(destination, outcome, event_count)
          return :permanent_failure
        end

        handle_dispatch_error(outcome.error, destination, outcome.error_category,
          redeliver: true, event_count: event_count)
        outcome.internal_error? ? :failed : :destination_error
      end

      def shadow_mode?
        ::Feature.enabled?(:audit_event_streaming_nats_shadow_mode, :instance)
      end
      strong_memoize_attr :shadow_mode?

      def skip_redelivery?(error_category)
        PERMANENT_ERROR_CATEGORIES.include?(error_category) && skip_permanent_failure_redelivery?
      end

      def skip_permanent_failure_redelivery?
        ::Feature.enabled?(:audit_event_streaming_nats_skip_permanent_failure_redelivery, :instance)
      end
      strong_memoize_attr :skip_permanent_failure_redelivery?

      def batch_stream_destination_for(destination)
        ::AuditEvents::Streaming::Destinations.for_category(destination.category).for_batch(destination)
      end

      # Filters need an event object (entity, streamable_namespace),
      # reconstructed from the in-message payload rather than fetched from
      # Postgres.
      #
      # A raise here is isolated to the offending payload (tracked and
      # excluded) so one bad event does not drop the rest of the batch for
      # this destination.
      def allowed_to_stream?(destination, payload)
        event = reconstructed_event(payload)
        return false unless event

        destination.allowed_to_stream?(payload['event_name'], event)
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, destination_id: destination.id, event_id: payload['id'])
        false
      end

      # Memoized per payload id: dispatch runs allowed_to_stream? once per
      # destination, so without this the event JSON is re-parsed up to
      # MAX_DESTINATIONS times per batch. Uses key? so a nil result (fetch
      # failure) is cached too, rather than re-fetched per destination.
      def reconstructed_event(payload)
        return reconstructed_events[payload['id']] if reconstructed_events.key?(payload['id'])

        reconstructed_events[payload['id']] = ::AuditEvents::Processor.fetch(
          audit_event_json: ::Gitlab::Json.generate(payload['event'])
        )
      end

      def reconstructed_events
        @reconstructed_events ||= {}
      end

      # Matches the single-event body contract: serialized event plus the
      # stable dedup id and event type.
      def event_body(payload)
        body = payload['event'].dup
        body['id'] = payload['id']
        body['event_type'] = payload['event_name']
        body
      end

      def log_slow_or_rejected_delivery(destination, outcome, batch_size)
        return unless outcome.slow_or_rejected?

        ::Gitlab::AppLogger.info(
          message: 'Audit event delivery slow or rejected',
          destination_id: destination.id,
          destination_category: destination.category,
          Labkit::Fields::GL_ROOT_NAMESPACE_ID => group_id,
          batch_size: batch_size,
          Labkit::Fields::DURATION_S => outcome.logged_duration_s,
          Labkit::Fields::HTTP_STATUS_CODE => outcome.status_code,
          error_category: outcome.error_category
        )
      end

      def handle_dispatch_error(error, destination, error_category, redeliver: true, event_count: nil)
        context = {
          destination_id: destination.id,
          destination_name: destination.name,
          destination_category: destination.category,
          error_category: error_category,
          redeliver: redeliver,
          event_count: event_count
        }.compact

        if error_category == :internal_error
          ::Gitlab::ErrorTracking.track_exception(error, context)
        else
          ::Gitlab::ErrorTracking.log_exception(error, context)
          ::AuditEvents::Streaming::CircuitBreaker.record_failure(destination)
        end
      end
    end
  end
end
