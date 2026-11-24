# frozen_string_literal: true

module Elastic
  class ProcessBookkeepingService
    SHARDS_MIN = 1
    SHARDS_MAX = 16
    SHARD_LIMIT = 1_000
    SHARDS = 0.upto(SHARDS_MAX - 1).to_a

    class << self
      def active_number_of_shards
        Gitlab::CurrentSettings.elasticsearch_worker_number_of_shards.clamp(self::SHARDS_MIN, self::SHARDS_MAX)
      end

      def shard_number(data)
        Elastic::BookkeepingShardService.shard_number(number_of_shards: active_number_of_shards, data: data)
      end

      def redis_set_key(shard_number)
        "elastic:incremental:updates:#{shard_number}:zset"
      end

      def redis_score_key(shard_number)
        "elastic:incremental:updates:#{shard_number}:score"
      end

      def redis_oldest_enqueued_at_key(shard_number)
        "#{redis_set_key(shard_number).delete_suffix(':zset')}:oldest_enqueued_at"
      end

      # Add some records to the processing queue. Items must be serializable to a Search::Elastic::Reference
      def track!(*items)
        return true if items.empty?

        # flatten! is temporary to support Vulnerabilities::Read - elastic_reference returning an array
        # when vulnerability_read_es_dual_write is enabled. Remove with the flag.
        items.map! { |item| ::Search::Elastic::Reference.serialize(item) }.flatten!

        items_by_shard = items.group_by { |item| shard_number(item) }

        with_redis do |redis|
          items_by_shard.each do |shard_number, shard_items|
            set_key = redis_set_key(shard_number)

            # Efficiently generate a guaranteed-unique score for each item
            max = redis.incrby(redis_score_key(shard_number), shard_items.size)
            min = (max - shard_items.size) + 1

            timeline_key = redis_oldest_enqueued_at_key(shard_number)
            Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
              redis.pipelined do |pipeline|
                (min..max).zip(shard_items).each_slice(1000) do |group|
                  logger.debug(
                    'class' => name,
                    'message' => 'track_items',
                    'meta.indexing.redis_set' => set_key,
                    'meta.indexing.count' => group.count,
                    'meta.indexing.tracked_items_encoded' => group.to_json
                  )

                  pipeline.zadd(set_key, group)
                end

                next unless track_timeline?

                pipeline.zadd(timeline_key, max, (Time.current.to_i / 60) * 60, gt: true)
              end
            end
          end
        end

        true
      end

      def queue_size
        with_redis do |redis|
          SHARDS.sum do |shard_number|
            redis.zcard(redis_set_key(shard_number))
          end
        end
      end

      # Unix timestamp the oldest still-queued item's batch was enqueued, or nil when empty.
      def oldest_enqueued_at
        with_redis do |redis|
          shard_min_scores = min_scores_by_shard(redis)
          oldest_timestamps(redis, shard_min_scores).compact.min if shard_min_scores.any?
        end
      end

      def queued_items
        {}.tap do |hash|
          with_redis do |redis|
            each_queued_items_by_shard(redis) do |shard_number, specs|
              hash[shard_number] = specs if specs.present?
            end
          end
        end
      end

      def clear_tracking!
        with_redis do |redis|
          Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
            keys = SHARDS.flat_map { |m| [redis_set_key(m), redis_score_key(m), redis_oldest_enqueued_at_key(m)] }

            if Gitlab::Redis::ClusterUtil.cluster?(redis)
              Gitlab::Redis::ClusterUtil.batch_unlink(keys, redis)
            else
              redis.unlink(*keys)
            end
          end
        end
      end

      def each_queued_items_by_shard(redis, shards: SHARDS, max_scores: {})
        (shards & SHARDS).each do |shard_number|
          yield shard_number, queued_specs(redis, shard_number, max_scores[shard_number])
        end
      end

      def max_score(shard_number)
        with_redis { |redis| redis.get(redis_score_key(shard_number)).to_i }
      end

      def logger
        # build already caches the logger via request store
        ::Gitlab::Elasticsearch::Logger.build
      end

      def with_redis(&blk)
        Gitlab::Redis::SharedState.with(&blk) # rubocop:disable CodeReuse/ActiveRecord
      end

      def maintain_indexed_associations(object, associations)
        each_indexed_association(object, associations) do |_, association|
          association.find_in_batches do |group|
            track!(*group)
          end
        end
      end

      def maintain_indexed_namespace_associations!(
        *namespaces, associations_to_index: [:epics, :milestones, :work_items]
      )
        namespaces.each do |namespace|
          next unless namespace.use_elasticsearch?

          associations = if namespace.group_namespace?
                           associations_to_index
                         else
                           associations_to_index - [:epics, :milestones]
                         end

          ElasticAssociationIndexerWorker.perform_async(namespace.class.name, namespace.id, associations.map(&:to_s))
        end
      end

      private

      def track_timeline?
        true
      end

      def queued_specs(redis, shard_number, max_score)
        # A lower counter means clear_tracking! ran after max_score was read.
        return [] if max_score && redis.get(redis_score_key(shard_number)).to_i < max_score

        redis.zrangebyscore(
          redis_set_key(shard_number), '-inf', max_score || '+inf', limit: [0, shard_limit], with_scores: true
        )
      end

      def min_scores_by_shard(redis)
        results = Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
          redis.pipelined do |pipeline|
            SHARDS.each do |shard_number|
              pipeline.zrangebyscore(redis_set_key(shard_number), '-inf', '+inf', limit: [0, 1], with_scores: true)
            end
          end
        end

        SHARDS.zip(results).filter_map do |shard_number, result|
          score = result.first&.last
          [shard_number, score] if score
        end.to_h
      end

      def oldest_timestamps(redis, shard_min_scores)
        results = Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
          redis.pipelined do |pipeline|
            shard_min_scores.each do |shard_number, min_score|
              pipeline.zrangebyscore(redis_oldest_enqueued_at_key(shard_number), min_score, '+inf', limit: [0, 1])
            end
          end
        end

        results.map { |result| result.first&.to_f }
      end

      def each_indexed_association(object, associations)
        associations.each do |association_name|
          association = object.association(association_name)
          scope = association.scope
          klass = association.klass
          scope = scope.searchable if [Note, Issue].include? klass
          scope = scope.with_group if klass == Milestone
          scope = scope.select(:id, :type) if [ProjectSnippet, Snippet].include? klass

          yield klass, scope
        end
      end

      def shard_limit
        SHARD_LIMIT
      end
    end

    # @param max_scores [Hash{Integer => Integer}] per shard, only process items scored at or below this
    def execute(shards: SHARDS, max_scores: {})
      self.class.with_redis { |redis| execute_with_redis(redis, shards: shards, max_scores: max_scores) }
    end

    private

    def current_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def execute_with_redis(redis, shards:, max_scores:) # rubocop:disable Metrics/AbcSize -- reads, indexes and removes a batch
      start_time = current_time

      specs_buffer = []
      scores = {}

      self.class.each_queued_items_by_shard(redis, shards: shards, max_scores: max_scores) do |shard_number, specs|
        next if specs.empty?

        set_key = self.class.redis_set_key(shard_number)
        first_score = specs.first.last
        last_score = specs.last.last

        logger.info(
          'class' => self.class.name,
          'message' => 'bulk_indexing_start',
          'meta.indexing.redis_set' => set_key,
          'meta.indexing.records_count' => specs.count,
          'meta.indexing.first_score' => first_score,
          'meta.indexing.last_score' => last_score
        )

        specs_buffer += specs

        scores[shard_number] = [set_key, first_score, last_score, specs.count]
      end

      return [0, 0] if specs_buffer.blank?

      indexing_durations = []
      refs = deserialize_all(specs_buffer)
      total_bytes = 0

      Search::Elastic::Reference.preload_database_records(refs).each do |ref|
        total_bytes += submit_document(ref)

        indexing_duration = ref.database_record&.try(:updated_at)&.then { |updated| Time.current - updated } || 0.0
        indexing_durations << indexing_duration
      end

      flushing_duration_s = Benchmark.realtime do
        @failures = bulk_indexer.flush
      end

      indexed_bytes_per_second = (total_bytes / (current_time - start_time)).ceil

      logger.info(
        'class' => self.class.name,
        'message' => 'bulk_indexer_flushed',
        'meta.indexing.search_flushing_duration_s' => flushing_duration_s,
        'meta.indexing.search_indexed_bytes_per_second' => indexed_bytes_per_second
      )
      Gitlab::Metrics::GlobalSearchIndexingSlis.record_bytes_per_second_apdex(
        throughput: indexed_bytes_per_second,
        target: indexing_bytes_per_second_target
      )

      # Route failures to retry queue or dead queue
      track_failures!(@failures)

      # Remove all the successes
      scores.each do |shard_number, (set_key, first_score, last_score, count)|
        redis.zremrangebyscore(set_key, first_score, last_score)

        trim_oldest_enqueued_at(redis, shard_number, set_key, last_score)

        logger.info(
          'class' => self.class.name,
          'message' => 'bulk_indexing_end',
          'meta.indexing.redis_set' => set_key,
          'meta.indexing.records_count' => count,
          'meta.indexing.first_score' => first_score,
          'meta.indexing.last_score' => last_score,
          'meta.indexing.failures_count' => @failures.count,
          'meta.indexing.bulk_execution_duration_s' => current_time - start_time
        )
      end

      refs.each_with_index do |ref, index|
        next if @failures.include?(ref)

        klass = ref.klass.to_s

        logger.info(
          'class' => self.class.name,
          'message' => 'indexing_done',
          'meta.indexing.reference_class' => klass,
          'meta.indexing.database_id' => ref.database_id,
          'meta.indexing.identifier' => ref.identifier,
          'meta.indexing.routing' => ref.routing,
          'meta.indexing.search_indexing_duration_s' => indexing_durations[index],
          'meta.indexing.search_indexing_flushing_duration_s' => flushing_duration_s
        )
      end

      [specs_buffer.count, @failures.count]
    end

    def deserialize_all(specs)
      refs = []
      specs.each do |spec, _|
        refs << Search::Elastic::Reference.deserialize(spec)
      rescue Search::Elastic::Reference::InvalidError, Search::Elastic::DocumentReference::InvalidError => err
        logger.error(
          'class' => self.class.name,
          'message' => 'submit_document_failed',
          'error_class' => err.class.to_s,
          'error_message' => err.message,
          'meta.indexing.reference' => spec
        )
      end

      refs.compact
    end

    def submit_document(ref)
      bulk_indexer.process(ref)
    end

    def bulk_indexer
      @bulk_indexer ||= ::Search::Elastic::BulkIndexer.new(logger: logger)
    end

    def logger
      self.class.logger
    end

    def indexing_bytes_per_second_target
      Gitlab::Metrics::GlobalSearchIndexingSlis::INCREMENTAL_INDEXED_BYTES_PER_SECOND_TARGET
    end

    def trim_oldest_enqueued_at(redis, shard_number, set_key, last_score)
      min_score = redis.zrangebyscore(set_key, '-inf', '+inf', limit: [0, 1], with_scores: true).first&.last
      max_drained = min_score ? "(#{min_score}" : last_score

      redis.zremrangebyscore(self.class.redis_oldest_enqueued_at_key(shard_number), '-inf', max_drained)
    end

    def track_failures!(failures)
      return if failures.empty?

      target_queue =
        if instance_of?(Search::Elastic::RetryQueue)
          Search::Elastic::DeadQueue
        else
          Search::Elastic::RetryQueue
        end

      target_queue.track!(*failures)
    end
  end
end
