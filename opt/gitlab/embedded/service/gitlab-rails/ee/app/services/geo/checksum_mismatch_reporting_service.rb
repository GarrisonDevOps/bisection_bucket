# frozen_string_literal: true

module Geo
  # Detects registries on a secondary that have persistently failed
  # verification due to a checksum mismatch, and reports them to the primary
  # so it can re-verify (recompute) its own checksum for those resources.
  #
  # See Geo::ChecksumMismatchSelfHealService for the primary-side handler.
  class ChecksumMismatchReportingService < RequestService
    include Gitlab::Geo::LogHelpers
    include Gitlab::Utils::StrongMemoize

    ERROR_TYPE = 'checksum_mismatch'
    # The primary rejects requests above this size, so it also bounds each request we send.
    BATCH_SIZE = ::Geo::VerificationFailureReportWorker::MAX_FAILURES_PER_REQUEST
    # Extra candidates fetched per replicable type so recently-reported ones
    # (skipped via the Redis dedup marker) don't starve the batch.
    CANDIDATE_MULTIPLIER = 3

    def initialize(geo_node)
      @geo_node = geo_node
    end

    def execute
      return false if mismatches.empty?

      # Candidates are collected per replicable type, so the total can exceed what the
      # primary accepts in one request. Send each slice separately so one rejection
      # doesn't block the rest.
      results = mismatches.each_slice(BATCH_SIZE).map do |slice|
        response = super(failures_url, payload(slice))

        mark_as_reported!(slice) if response

        response
      end

      results.all?
    end

    private

    attr_reader :geo_node

    def failures_url
      primary_node&.checksum_mismatch_reports_url
    end
    strong_memoize_attr :failures_url

    def payload(failures)
      { geo_node_id: geo_node.id, failures: failures }
    end

    def mismatches
      @mismatches ||= Gitlab::Geo.repository_replicator_classes.flat_map do |replicator_class|
        candidates_for(replicator_class)
      end
    end

    # rubocop:disable CodeReuse/ActiveRecord -- chained on the persistent_checksum_mismatches model scope, iterating over registry classes with no single model to place this on
    def candidates_for(replicator_class)
      replicable_name = replicator_class.replicable_name

      registries = replicator_class.registry_class
        .persistent_checksum_mismatches(geo_node.checksum_mismatch_report_threshold)
        .order(:verification_retry_at)
        .limit(BATCH_SIZE * CANDIDATE_MULTIPLIER)
        .to_a

      already_reported = recently_reported_ids(replicable_name, registries.map(&:model_record_id))

      registries
        .reject { |registry| already_reported.include?(registry.model_record_id) }
        .first(BATCH_SIZE)
        .map { |registry| build_entry(replicable_name, registry) }
    end
    # rubocop:enable CodeReuse/ActiveRecord

    def build_entry(replicable_name, registry)
      {
        error_type: ERROR_TYPE,
        replicable_name: replicable_name,
        replicable_id: registry.model_record_id,
        verification_retry_count: registry.verification_retry_count,
        context: { primary_checksum_at_mismatch: registry.verification_checksum_mismatched }
      }
    end

    # Batches the dedup existence checks into a single pipelined round trip
    # per replicable type, instead of one Redis call per candidate.
    def recently_reported_ids(replicable_name, replicable_ids)
      return [] if replicable_ids.empty?

      results = with_dedup_pipeline do |pipeline|
        replicable_ids.each { |id| pipeline.exists?(dedup_cache_key(replicable_name, id)) } # rubocop:disable CodeReuse/ActiveRecord -- not ActiveRecord
      end

      replicable_ids.zip(results).filter_map { |id, reported| id if reported }
    end

    def mark_as_reported!(entries)
      ttl = geo_node.checksum_mismatch_self_heal_cooldown_minutes.minutes

      with_dedup_pipeline do |pipeline|
        entries.each do |entry|
          pipeline.set(dedup_cache_key(entry[:replicable_name], entry[:replicable_id]), 1, ex: ttl.to_i)
        end
      end
    end

    # Dedup keys hash to different slots; `pipelined` splits commands per node on Redis Cluster.
    def with_dedup_pipeline(&block)
      Gitlab::Redis::SharedState.with do |redis|
        Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
          redis.pipelined(&block)
        end
      end
    end

    def dedup_cache_key(replicable_name, replicable_id)
      "geo:checksum_mismatch_reported:#{replicable_name}:#{replicable_id}"
    end
  end
end
