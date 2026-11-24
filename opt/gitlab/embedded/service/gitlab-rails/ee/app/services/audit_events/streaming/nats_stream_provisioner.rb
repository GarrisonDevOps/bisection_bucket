# frozen_string_literal: true

module AuditEvents
  module Streaming
    # Idempotently provisions the JetStream stream that backs audit event
    # streaming and its per-partition durable consumers, and is the single
    # source of truth for their desired config.
    #
    # Runs in two contexts:
    #   - the `gitlab:audit_events:streaming:nats:ensure_stream` rake task
    #   - runtime safety net: `ensure_once!` under an ExclusiveLease from the
    #     scheduler cron, at most once per STREAM_ENSURE_INTERVAL
    class NatsStreamProvisioner
      include ::Gitlab::Loggable

      STREAM_NAME = 'audit_events_streaming'
      SUBJECT_FILTER = "#{::AuditEvents::Streaming::NatsPartitioning::SUBJECT_PREFIX}.*".freeze

      RETENTION = :limits
      STORAGE = :file
      # JetStream rejects num_replicas > 1 on a non-clustered server, so dev
      # (GDK) uses 1 via Settings.nats.stream_replicas; production uses 3.
      DEFAULT_NUM_REPLICAS = 1
      MAX_AGE = 24.hours
      DUPLICATE_WINDOW = 2.minutes

      # The first value is the ack deadline. It is above the drainer's 65s lease,
      # so a batch a drainer is still sending is not redelivered to the next one.
      # The last value repeats until CONSUMER_MAX_DELIVER.
      CONSUMER_BACKOFF = [2.minutes, 5.minutes, 15.minutes, 30.minutes, 1.hour].freeze
      # About 6h of redelivery, well inside MAX_AGE. Messages that reach it stay
      # readable by stream sequence until MAX_AGE and raise a MAX_DELIVERIES advisory.
      CONSUMER_MAX_DELIVER = 10
      # JetStream server defaults, restored when the redelivery flag is disabled.
      DEFAULT_CONSUMER_ACK_WAIT = 30.seconds
      DEFAULT_CONSUMER_MAX_DELIVER = -1

      ENSURE_LEASE_KEY = 'audit_events:streaming:nats:ensure_stream'
      # Lease-guarded re-check cadence: short enough that a missing stream
      # self-heals promptly, above the 1-minute cron so we skip most ticks.
      STREAM_ENSURE_INTERVAL = 5.minutes

      Result = Struct.new(:action, :stream_info)

      class << self
        # Lease-guarded ensure for the hot-adjacent cron path: runs at most
        # once per STREAM_ENSURE_INTERVAL cluster-wide. Returns nil when
        # another node holds the lease (i.e. it ran recently).
        #
        # On success the lease is retained (expires naturally) so it acts as a
        # rate limiter. On failure the lease is cancelled so the next cron tick
        # retries immediately, rather than blocking provisioning for the full
        # STREAM_ENSURE_INTERVAL after a transient error.
        #
        # @return [Result, nil]
        def ensure_once!
          lease = ::Gitlab::ExclusiveLease.new(ENSURE_LEASE_KEY, timeout: STREAM_ENSURE_INTERVAL.to_i)
          uuid = lease.try_obtain
          return unless uuid

          new.ensure!
        rescue StandardError
          ::Gitlab::ExclusiveLease.cancel(ENSURE_LEASE_KEY, uuid) if uuid
          raise
        end
      end

      # Ensures the stream, then every partition's durable consumer.
      #
      # @return [Result] action is the stream's :created, :updated, or :exists
      def ensure!
        result = ensure_stream!
        ensure_consumers!

        result
      end

      def info
        client.stream_info(STREAM_NAME)
      end

      def desired_config
        {
          name: STREAM_NAME,
          subjects: [SUBJECT_FILTER],
          retention: RETENTION,
          storage: STORAGE,
          num_replicas: num_replicas,
          max_age: MAX_AGE.to_i * 1_000_000_000, # JetStream expects nanoseconds
          duplicate_window: DUPLICATE_WINDOW.to_i * 1_000_000_000
        }
      end

      # @param key [Integer, String] a partition key from NatsPartitioning.partition_keys
      # @return [Hash] consumer config in the form Gitlab::Nats::Client#add_consumer takes
      def desired_consumer_config(key)
        {
          durable_name: ::AuditEvents::Streaming::NatsPartitioning.durable_for_key(key),
          filter_subject: ::AuditEvents::Streaming::NatsPartitioning.subject_for_key(key),
          ack_policy: 'explicit',
          **redelivery_config
        }
      end

      private

      def client
        ::Gitlab::Nats.client
      end

      def ensure_stream!
        info = client.stream_info(STREAM_NAME)

        return Result.new(:exists, info) if info && config_matches?(info)

        if info
          updated = client.update_stream(desired_config)
          log(:updated)
          Result.new(:updated, updated)
        else
          created = client.add_stream(desired_config)
          log(:created)
          Result.new(:created, created)
        end
      end

      # Drainers bind with pull_subscribe, which never reapplies config to an
      # existing durable, so the config is set and drift is corrected here.
      def ensure_consumers!
        ::AuditEvents::Streaming::NatsPartitioning.partition_keys.each do |key|
          desired = desired_consumer_config(key)
          info = client.consumer_info(STREAM_NAME, desired[:durable_name])

          next if info && consumer_config_matches?(info.config, desired)

          client.add_consumer(STREAM_NAME, desired)
          log_consumer(info ? :updated : :created, desired[:durable_name])
        end
      end

      def redelivery_config
        unless ::Feature.enabled?(:audit_event_streaming_nats_consumer_redelivery, :instance)
          return { ack_wait: DEFAULT_CONSUMER_ACK_WAIT.to_i, max_deliver: DEFAULT_CONSUMER_MAX_DELIVER }
        end

        {
          ack_wait: CONSUMER_BACKOFF.first.to_i,
          max_deliver: CONSUMER_MAX_DELIVER,
          backoff: CONSUMER_BACKOFF.map { |interval| interval.to_i * 1_000_000_000 } # JetStream expects nanoseconds
        }
      end

      # nats-pure returns ack_wait in seconds and backoff in nanoseconds, the
      # same units desired_consumer_config uses.
      def consumer_config_matches?(config, desired)
        config.ack_wait.to_i == desired[:ack_wait] &&
          config.max_deliver.to_i == desired[:max_deliver] &&
          Array(config.backoff) == Array(desired[:backoff])
      end

      def num_replicas
        ::Settings.nats&.stream_replicas || DEFAULT_NUM_REPLICAS
      end

      def config_matches?(info)
        config = info.respond_to?(:config) ? info.config : info

        Array(config_value(config, :subjects)).sort == desired_config[:subjects].sort &&
          config_value(config, :num_replicas).to_i == desired_config[:num_replicas] &&
          config_value(config, :max_age).to_i == desired_config[:max_age] &&
          config_value(config, :duplicate_window).to_i == desired_config[:duplicate_window]
      end

      # Reads a field from either a nats-pure config struct or a plain Hash.
      def config_value(config, key)
        return config[key] || config[key.to_s] if config.is_a?(Hash)

        case key
        when :subjects then config.subjects if config.respond_to?(:subjects)
        when :num_replicas then config.num_replicas if config.respond_to?(:num_replicas)
        when :max_age then config.max_age if config.respond_to?(:max_age)
        when :duplicate_window then config.duplicate_window if config.respond_to?(:duplicate_window)
        end
      end

      def log(action)
        ::Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            message: 'NATS audit event streaming stream provisioned',
            stream: STREAM_NAME,
            action: action
          )
        )
      end

      def log_consumer(action, consumer)
        ::Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            message: 'NATS audit event streaming consumer provisioned',
            stream: STREAM_NAME,
            consumer: consumer,
            action: action
          )
        )
      end
    end
  end
end
