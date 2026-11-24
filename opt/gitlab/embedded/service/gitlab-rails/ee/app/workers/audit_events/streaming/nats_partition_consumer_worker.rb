# frozen_string_literal: true

module AuditEvents
  module Streaming
    # Drains a single NATS partition and dispatches its audit events to
    # external streaming destinations in batches.
    #
    # Mutual exclusion: exactly one drainer per partition runs at a time. Events
    # are routed to random partitions (see NatsPartitioning). Concurrent drainers
    # would not double-fetch (JetStream hands each pull distinct messages from the
    # shared durable), but a slow drainer's un-acked messages would hit AckWait
    # and be redelivered to the other drainer, causing duplicate dispatch and
    # ack-pending contention. The lease caps the durable to one puller to avoid that.
    # It uses a short, self-set ExclusiveLease rather than Sidekiq dedup, whose 10-minute TTL
    # would starve a partition if a run died without cleanup.
    #
    # Delivery is at-least-once: a batch's messages are acked only after a
    # successful dispatch; failures are left unacked for JetStream redelivery,
    # and consumers deduplicate via the stable event ID in the payload.
    # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- parity with the legacy AuditEvents::AuditEventStreamingWorker, which does equivalent destination-config/event-reconstruction DB work without a health gate; deferring here would stop NATS draining under DB stress while the legacy path keeps delivering. Load is already bounded by concurrency_limit and the per-partition lease
    class NatsPartitionConsumerWorker
      include ApplicationWorker

      idempotent! # safe to re-run: unacked messages redeliver, acked ones do not
      # One drainer per partition comes from the per-partition ExclusiveLease
      # (#in_lease, see the class comment); Sidekiq dedup would be redundant and
      # could stall a partition for its TTL.
      deduplicate :none
      worker_has_external_dependencies!
      data_consistency :sticky
      feature_category :audit_events
      urgency :low
      loggable_arguments 0
      # Cap in-flight drainers at the partition count so a full fan-out cannot
      # saturate the shard.
      concurrency_limit -> { ::AuditEvents::Streaming::NatsPartitioning.partition_keys.size }

      PoisonMessageError = Class.new(StandardError)

      BATCH_SIZE = 100
      MAX_RUN_TIME = 50.seconds # exit before the next 1-minute cron tick
      PULL_TIMEOUT = 5 # seconds
      # Longer than MAX_RUN_TIME so a full-length drain keeps its lease, short
      # enough that a crashed drainer's partition resumes on the next tick.
      LEASE_TIMEOUT = 65.seconds

      # @param key [Integer, String] partition key: a numeric partition index
      #   or NatsPartitioning::INSTANCE_KEY for the instance-scoped lane.
      def perform(key)
        return if ::Gitlab::SilentMode.enabled?
        return unless ::Gitlab::Nats.enabled?
        return unless Feature.enabled?(:audit_event_streaming_nats_consumer, :instance) # -- instance-wide kill switch

        in_lease(key) { |lease| drain(key, lease) }
      end

      private

      def in_lease(key)
        lease = ::Gitlab::ExclusiveLease.new(lease_key(key), timeout: LEASE_TIMEOUT)
        uuid = lease.try_obtain

        # Another drainer already owns this partition; exit cleanly. The next
        # cron tick reschedules, preserving single-drainer-per-partition.
        return unless uuid

        yield lease
      ensure
        ::Gitlab::ExclusiveLease.cancel(lease_key(key), uuid) if uuid
      end

      def lease_key(key)
        "audit_events:streaming:nats:partition:#{key}"
      end

      def drain(key, lease)
        subscription = subscribe(key)
        runtime_limiter = ::Gitlab::Metrics::RuntimeLimiter.new(MAX_RUN_TIME)
        dispatched_count = 0

        loop do
          messages = fetch_batch(subscription)
          break if messages.empty?

          dispatched_count += process_batch(key, messages)

          # A short batch means the partition is drained for now. With volume
          # spread evenly across partitions every partition has a steady
          # trickle, so without this a drainer would hold a Sidekiq thread for
          # the full MAX_RUN_TIME every tick. The next cron tick picks up more.
          break if messages.size < BATCH_SIZE

          break if runtime_limiter.over_time?

          # Stop if we lost the lease: renew returns false once it expired or
          # another drainer took over. Continuing would put two pullers on the
          # durable, so a slow ack here could be redelivered to the other and
          # dispatched twice (see the class comment).
          break unless lease.renew
        end

        log_extra_metadata_on_done(:partition, key)
        log_extra_metadata_on_done(:dispatched_message_count, dispatched_count)
      rescue ::NATS::JetStream::Error::NotFound => e
        # Stream not provisioned yet (first run before ensure_once! created it).
        # Exit cleanly so the job is not retried; the next tick reschedules.
        skip(key, 'stream_not_found', detail: e.message)
      rescue ::Gitlab::Nats::Client::ConnectionError => e
        # NATS is unreachable. Exit cleanly rather than raising: one drainer
        # per partition would otherwise turn a broker outage into a Sidekiq
        # retry storm. The next cron tick reschedules once the server is back.
        ::Gitlab::Metrics::AuditEventStreamingSlis.record_consumer_unreachable
        skip(key, 'nats_unreachable', detail: e.message)
      ensure
        # The client memoizes one long-lived connection per process; without
        # this each drainer would leak its subscription and inbox on it. Guard
        # the teardown: on a dropped connection unsubscribe itself raises, and
        # an ensure that raises would escape the rescues above.
        begin
          subscription&.unsubscribe
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
        end
      end

      def skip(key, reason, detail: nil)
        log_extra_metadata_on_done(:partition, key)
        log_extra_metadata_on_done(:skipped, reason)
        log_extra_metadata_on_done(:skipped_detail, detail) if detail
      end

      def subscribe(key)
        ::Gitlab::Nats.client.pull_subscribe(
          ::AuditEvents::Streaming::NatsPartitioning.subject_for_key(key),
          durable: ::AuditEvents::Streaming::NatsPartitioning.durable_for_key(key)
        )
      end

      def fetch_batch(subscription)
        Array(subscription.fetch(BATCH_SIZE, timeout: PULL_TIMEOUT))
      rescue ::NATS::Timeout
        # No messages available within the pull window; the partition is drained.
        []
      end

      # Groups messages by root group so per-group work (destination config,
      # filtering) runs once per (group x batch). Returns the dispatched count.
      def process_batch(key, messages)
        entries = messages.filter_map { |message| parse(message) }
        observe_fetch_lag(entries)

        entries.group_by { |entry| entry[:payload]['group_id'] }.sum do |group_id, group_entries|
          dispatch_group(key, group_id, group_entries)
        end
      end

      def parse(message)
        payload = ::Gitlab::Json.safe_parse(message.data)

        return { message: message, payload: payload } if payload.is_a?(Hash)

        discard_poison_message(message)
      rescue JSON::ParserError
        discard_poison_message(message)
      end

      # Redelivery will never succeed, so ack it away. Logs only identifiers,
      # never the payload body (it holds actor/IP/target compliance data), and
      # tracks the discard so dropped audit events alert.
      def discard_poison_message(message)
        error = PoisonMessageError.new('Discarding unparseable NATS audit event message')
        context = {
          subject: message.subject,
          stream_sequence: message.metadata&.sequence&.stream,
          byte_size: message.data.to_s.bytesize
        }

        ::Gitlab::ErrorTracking.track_exception(error, context)
        ::Gitlab::AppJsonLogger.warn(
          context.merge(
            ::Labkit::Fields::CLASS_NAME => self.class.name,
            ::Labkit::Fields::LOG_MESSAGE => error.message
          )
        )
        message.ack

        nil
      end

      # Acks the group's messages only when execute reports full delivery (see
      # BatchedDispatcher#execute); otherwise they stay unacked to redeliver.
      def dispatch_group(key, group_id, entries)
        payloads = entries.map { |entry| entry[:payload] } # rubocop:disable Rails/Pluck -- plain Hash entries, not an ActiveRecord relation

        dispatch_outcome = deliver_batch(group_id, payloads)

        case dispatch_outcome
        when :destination_error
          # Not GitLab's fault (unreachable endpoint, bad credentials); record
          # as degradation, not an SLI error. Left unacked so it redelivers.
          ::Gitlab::Metrics::AuditEventStreamingSlis.record_dispatch_destination_error
          record_max_deliveries(key, group_id, entries, dispatch_outcome)
          return 0
        when :failed
          ::Gitlab::Metrics::AuditEventStreamingSlis.record_dispatch(result: :failure)
          record_max_deliveries(key, group_id, entries, dispatch_outcome)
          return 0
        end

        # Delivery is committed here. Post-ack bookkeeping runs outside the
        # failure path so a later error (e.g. from observe_lag) cannot flip an
        # acked success back to a recorded failure.
        ::Gitlab::Metrics::AuditEventStreamingSlis.record_dispatch(result: :success)
        ack_entries(entries)
        observe_lag(payloads)

        entries.size
      end

      # Scoped to the delivery decision only. An unexpected raise here (e.g. a
      # destination-config lookup) is a GitLab-side failure, so the messages
      # stay unacked (JetStream redelivers) and it counts against the SLI.
      #
      # @return [Symbol] :delivered, :destination_error, or :failed
      def deliver_batch(group_id, payloads)
        ::AuditEvents::Streaming::BatchedDispatcher.new(group_id, payloads).execute
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, group_id: group_id)
        :failed
      end

      # A failure on delivery number max_deliver is the last one: JetStream stops
      # redelivering the message. Logs identifiers only, never the event body.
      def record_max_deliveries(key, group_id, entries, outcome)
        return unless ::Feature.enabled?(:audit_event_streaming_nats_consumer_redelivery, :instance)

        consumer = ::AuditEvents::Streaming::NatsPartitioning.durable_for_key(key)

        entries.each do |entry|
          metadata = entry[:message].metadata
          next unless last_delivery?(metadata)

          ::Gitlab::Metrics::AuditEventStreamingSlis.record_max_delivery(consumer: consumer)
          ::Gitlab::AppJsonLogger.warn(
            ::Labkit::Fields::CLASS_NAME => self.class.name,
            ::Labkit::Fields::LOG_MESSAGE => 'NATS audit event message failed on its last allowed delivery',
            stream_sequence: metadata.sequence&.stream,
            audit_event_id: entry[:payload]['id']&.to_s,
            ::Labkit::Fields::GL_NAMESPACE_ID => group_id,
            consumer: consumer,
            partition: key.to_s,
            num_delivered: metadata.num_delivered,
            outcome: outcome.to_s
          )
        end
      rescue StandardError => e
        # Best-effort bookkeeping: never let it change the dispatch outcome.
        ::Gitlab::ErrorTracking.track_exception(e)
      end

      # Above the limit too: messages already past it when the flag was enabled.
      def last_delivery?(metadata)
        return false unless metadata

        metadata.num_delivered >= ::AuditEvents::Streaming::NatsStreamProvisioner::CONSUMER_MAX_DELIVER
      end

      def ack_entries(entries)
        entries.each { |entry| entry[:message].ack }
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e)
      end

      # Recorded on every delivery, before dispatch, so messages that keep
      # failing still report their age. observe_lag only sees acked messages.
      def observe_fetch_lag(entries)
        now = Time.current

        entries.each do |entry|
          published_at = entry[:payload]['published_at']
          next unless published_at

          ::Gitlab::Metrics::AuditEventStreamingSlis.observe_fetch_lag(
            now - Time.iso8601(published_at),
            redelivered: (entry[:message].metadata&.num_delivered || 1) > 1
          )
        rescue StandardError => e
          # Best-effort telemetry, per message: one bad message must not hide
          # the others' ages or stop the batch from being dispatched.
          ::Gitlab::ErrorTracking.track_exception(e)
        end
      end

      def observe_lag(payloads)
        payloads.each do |payload|
          published_at = payload['published_at']
          next unless published_at

          # NTP skew between hosts can make this slightly negative; observe_lag drops those.
          lag = Time.current - Time.iso8601(published_at)
          ::Gitlab::Metrics::AuditEventStreamingSlis.observe_lag(lag)
        end
      rescue StandardError => e
        # Lag is best-effort telemetry recorded after messages are acked; never
        # let it raise and turn an already-committed dispatch into a job failure.
        ::Gitlab::ErrorTracking.track_exception(e)
      end
    end
    # rubocop:enable Sidekiq/EnforceDatabaseHealthSignalDeferral
  end
end
