# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      class ReenqueueOrphanedRefs < ::ActiveContext::Task[1.0]
        include Gitlab::Utils::StrongMemoize
        include Concerns::CollectionLookup
        include Ai::ActiveContext::Concerns::Loggable

        batched!

        SHARD_READ_LIMIT = 1_000

        def required_params
          %w[collection queue_shards]
        end

        def execute!
          validate_collection_record!

          unless has_orphaned_queue_shards?
            log_no_orphaned_shards
            return
          end

          track_orphaned_refs
        end

        def completed?
          time_elapsed_since_update = Time.current - task_record.created_at
          return false if time_elapsed_since_update.to_f <= ::ActiveContext::CollectionCache::TTL.to_f

          validate_collection_record!

          !has_orphaned_queue_shards? || queue_shards_empty?
        end

        private

        def validate_collection_record!
          # The collection record holds the `queue_shard_count` value,
          # so we need to make sure it exists
          raise TaskError, "Collection '#{collection_name}' not found" unless collection_record
        end

        def collection_record
          ::Ai::ActiveContext::Collection.find_by_name(
            connection, full_collection_name(collection_name)
          )
        end
        strong_memoize_attr :collection_record

        def orphaned_queue_shards
          # Get the actual orphaned shards, which is any shard number
          # greater than or equal to the current `queue_shard_count`
          queue_shards.select { |n| n >= current_queue_shard_count }
        end
        strong_memoize_attr :orphaned_queue_shards

        def has_orphaned_queue_shards?
          orphaned_queue_shards.present?
        end

        def queue_shards_empty?
          queue_class.queue_size(shards: orphaned_queue_shards, include_orphaned: true) == 0
        end

        def track_orphaned_refs
          ::ActiveContext::Redis.with_redis do |redis|
            each_queued_items_by_shard(redis) do |shard_number, scored_refs|
              if scored_refs.empty?
                log_orphaned_shard_is_empty(shard_number)
                next
              end

              refs_to_reenqueue, min_score, max_score = extract_refs_and_score_range(scored_refs)

              collection_class.track!(refs_to_reenqueue)
              queue_class.remove_shard_items(redis, shard_number, min_score, max_score)

              log_refs_reenqueued(shard_number, scored_refs.length, min_score, max_score)
            end
          end
        end

        def extract_refs_and_score_range(scored_refs)
          refs = []
          scores = []

          scored_refs.each do |scored_ref|
            _collection_id, routing, ref_key = reference_class.deserialize_string(scored_ref.first)

            refs << { id: ref_key, routing: routing.to_i }
            scores << scored_ref.second
          end

          [refs, scores.min, scores.max]
        end

        def each_queued_items_by_shard(redis, &block)
          queue_class.each_queued_items_by_shard(
            redis, shards: orphaned_queue_shards, include_orphaned: true, limit: SHARD_READ_LIMIT, &block
          )
        end

        def reference_class
          collection_class.reference_klass
        end

        def queue_class
          collection_class.queue
        end

        def current_queue_shard_count
          @current_queue_shard_count ||= queue_class.number_of_shards
        end

        def queue_shards
          @queue_shards ||= params['queue_shards']
        end

        def log_no_orphaned_shards
          logger.info(
            build_structured_payload(
              message: 'No orphaned shards found.'
            )
          )
        end

        def log_orphaned_shard_is_empty(shard_number)
          logger.info(
            build_structured_payload(
              message: 'Orphaned shard is already empty.',
              orphaned_shard: shard_number
            )
          )
        end

        def log_refs_reenqueued(shard_number, refs_count, min_score, max_score)
          logger.info(
            build_structured_payload(
              message: 'References reenqueued to active shards.',
              orphaned_shard: shard_number,
              count: refs_count,
              min_score: min_score,
              max_score: max_score
            )
          )
        end
      end
    end
  end
end
