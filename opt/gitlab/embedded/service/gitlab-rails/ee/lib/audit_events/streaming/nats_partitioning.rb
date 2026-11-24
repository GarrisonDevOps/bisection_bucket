# frozen_string_literal: true

module AuditEvents
  module Streaming
    # Shared partitioning scheme for the NATS audit event streaming pipeline.
    #
    # Subjects are partitioned into a fixed number of partitions rather than
    # one subject per group. There are millions of top-level groups, far beyond
    # what a single JetStream stream can track as distinct subjects (subject
    # state is held in memory), so a fixed partition count keeps subject
    # cardinality constant regardless of group count.
    #
    # Partition selection is random, not derived from the group ID. Deriving it
    # from the group ID (group_id % partition_count) spread group IDs evenly but
    # not volume: audit traffic is heavily skewed toward a few large namespaces,
    # so their partitions reached millions of pending messages while a single
    # drainer per partition capped throughput, leaving most of the fleet idle
    # (see https://gitlab.com/gitlab-org/gitlab/-/issues/604456). Spreading each
    # event to a random partition evens out volume and lets many drainers work
    # a hot tenant in parallel.
    #
    # This drops per-group FIFO ordering: a group's events now scatter across
    # partitions and can be delivered out of order. That is acceptable because
    # the legacy per-event Sidekiq path (AuditEvents::AuditEventStreamingWorker)
    # never guaranteed ordering either, and receivers deduplicate on the stable
    # event ID.
    #
    # Partition counts are configurable per installation (Settings.nats). There
    # are two:
    #   - drain_partition_count: how many partitions (and durable consumers) the
    #     pipeline provisions and drains, one worker per partition. This sets
    #     consumer parallelism.
    #   - publish_partition_count: how many of those partitions publishing spreads
    #     across, capped at the drain count so an event is never routed to a
    #     partition no consumer drains.
    # Both default to a single partition, so a small install carries no extra
    # overhead; a high-volume deployment raises them. Keeping them separate lets
    # the topology scale up safely on a live stream: raise the drain count and
    # provision/fan out the new consumers first, then raise the publish count, so
    # new subjects always have a drainer before any event lands on them (see
    # https://gitlab.com/gitlab-org/gitlab/-/issues/622750).
    #
    # Cells: subjects are not qualified by cell or environment. If the
    # JetStream cluster is ever shared across cells, group IDs are not unique
    # across cells and subjects would collide. Isolation therefore relies on
    # each cell owning its own stream (or NATS account); see the stream
    # provisioner. Do not share a stream across cells without a qualifier.
    #
    # Invalid input: subject_for still validates the group ID and raises
    # ArgumentError/TypeError on a malformed one (even though the ID no longer
    # determines the partition), rather than silently routing it. The publish
    # caller runs on an audited request path, so it must treat NATS routing as
    # best-effort: rescue the error, fall back to the Sidekiq streaming path,
    # and never let an instrumentation failure break the audited action.
    module NatsPartitioning
      # Default partition count: a single partition, safe for a small install.
      # High-volume deployments (e.g. GitLab.com) raise it via Settings.nats.
      DEFAULT_PARTITION_COUNT = 1
      SUBJECT_PREFIX = 'audit_events.streaming'
      DURABLE_PREFIX = 'audit_streaming_consumer'

      # Instance-scoped (admin) events have no root group. They get a
      # dedicated subject and durable rather than a numeric partition so they
      # are never stuck behind a tenant's backlog: routing them through a
      # shared numeric partition would block them behind roughly
      # 1/partition_count of groups. One extra subject fully isolates them.
      #
      # INSTANCE_KEY is the partition key used by the scheduler and consumer
      # worker for this dedicated lane (alongside the integer partitions).
      INSTANCE_KEY = 'instance'
      INSTANCE_SUBJECT = "#{SUBJECT_PREFIX}.#{INSTANCE_KEY}".freeze
      INSTANCE_DURABLE = "#{DURABLE_PREFIX}_#{INSTANCE_KEY}".freeze

      module_function

      # Every partition key the pipeline drains: one per numeric partition plus
      # the dedicated instance lane. The consumer scheduler fans out over this.
      #
      # @return [Array<Integer, String>]
      def partition_keys
        [*0...drain_partition_count, INSTANCE_KEY]
      end

      # @return [Integer] numeric partitions (and durable consumers) provisioned
      #   and drained
      def drain_partition_count
        count_setting(:drain_partition_count)
      end

      # Capped at the drain count so an event is never routed to a partition no
      # consumer drains.
      #
      # @return [Integer] numeric partitions a publish may target
      def publish_partition_count
        [count_setting(:publish_partition_count), drain_partition_count].min
      end

      # Picks a random partition for a group event, spreading volume evenly
      # instead of by group ID (see the module docs).
      #
      # @param group_id [Integer, String, nil] top-level group ID (Integer or
      #   its string form), or nil for instance-scoped events
      # @return [Integer, nil] a random partition index in
      #   [0, publish_partition_count), or nil for instance-scoped events
      # @raise [ArgumentError, TypeError] if group_id is present but not a
      #   valid integer
      def publish_partition_for(group_id)
        # Only a true nil means instance-scoped. Use nil? (not blank?) so an
        # empty string or other malformed id fails loudly below rather than
        # being silently routed to the instance lane, and so the module stays
        # free of the ActiveSupport blank? dependency.
        return if group_id.nil?

        # Validate only: a malformed id must still raise, but the value is
        # discarded since the partition is random.
        Integer(group_id)
        rand(publish_partition_count)
      end

      # @param group_id [Integer, String, nil]
      # @return [String] a randomly chosen partition subject for the group, or
      #   INSTANCE_SUBJECT for instance-scoped events
      def subject_for(group_id)
        partition = publish_partition_for(group_id)
        return INSTANCE_SUBJECT if partition.nil?

        subject_for_partition(partition)
      end

      # @param key [Integer, String] a numeric partition index (Integer or its
      #   string form), or INSTANCE_KEY
      # @return [String] the subject for that partition key
      # @raise [ArgumentError] if key is neither a valid partition nor INSTANCE_KEY
      def subject_for_key(key)
        return INSTANCE_SUBJECT if instance_key?(key)

        subject_for_partition(coerce_partition(key))
      end

      # @param key [Integer, String] a numeric partition index (Integer or its
      #   string form), or INSTANCE_KEY
      # @return [String] the durable consumer name for that partition key
      # @raise [ArgumentError] if key is neither a valid partition nor INSTANCE_KEY
      def durable_for_key(key)
        return INSTANCE_DURABLE if instance_key?(key)

        durable_for_partition(coerce_partition(key))
      end

      # @param partition [Integer] partition index in [0, drain_partition_count)
      # @return [String] e.g. "audit_events.streaming.42"
      # @raise [ArgumentError] if partition is out of range
      def subject_for_partition(partition)
        validate_partition!(partition)

        "#{SUBJECT_PREFIX}.#{partition}"
      end

      # @param partition [Integer] partition index in [0, drain_partition_count)
      # @return [String] durable consumer name for a partition
      # @raise [ArgumentError] if partition is out of range
      def durable_for_partition(partition)
        validate_partition!(partition)

        "#{DURABLE_PREFIX}_#{partition}"
      end

      # Validates against the drain count (the full provisioned range), so a
      # drainer can resolve the subject/durable for any partition it owns.
      #
      # @param partition [Integer]
      # @raise [ArgumentError] unless partition is in [0, drain_partition_count)
      def validate_partition!(partition)
        count = drain_partition_count
        return if partition.is_a?(Integer) && (0...count).cover?(partition)

        raise ArgumentError, "partition must be in [0, #{count}), got #{partition.inspect}"
      end

      # A partition key round-trips through Sidekiq args (YAML), Redis, and
      # NATS headers, any of which can stringify it. Match the instance lane by
      # value so both :instance / "instance" and an integer / its string form
      # resolve correctly.
      #
      # @param key [Integer, String]
      # @return [Boolean]
      def instance_key?(key)
        key.to_s == INSTANCE_KEY
      end

      # Coerces a numeric partition key (Integer or its string form) to an
      # Integer, so a stringified key does not blow up validate_partition!.
      # nil and other non-numeric input raise ArgumentError (not TypeError) so
      # subject_for_key / durable_for_key keep a single documented failure mode.
      #
      # @param key [Integer, String]
      # @return [Integer]
      # @raise [ArgumentError] if key is not a valid integer
      def coerce_partition(key)
        Integer(key)
      rescue TypeError
        raise ArgumentError, "partition key must be an integer or its string form, got #{key.inspect}"
      end

      # Floors at 1 so a misconfigured zero or negative never yields an empty
      # topology (no partitions to publish to or drain).
      #
      # @param key [Symbol]
      # @return [Integer]
      def count_setting(key)
        value = ::Settings.nats&.public_send(key) # rubocop:disable GitlabSecurity/PublicSend -- key is a fixed internal symbol
        return DEFAULT_PARTITION_COUNT if value.nil?

        [value.to_i, 1].max
      end
      private_class_method :count_setting
    end
  end
end
