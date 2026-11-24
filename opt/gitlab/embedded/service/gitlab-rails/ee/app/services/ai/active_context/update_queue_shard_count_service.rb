# frozen_string_literal: true

module Ai
  module ActiveContext
    class UpdateQueueShardCountService
      include Gitlab::Utils::StrongMemoize
      include Ai::ActiveContext::Concerns::Loggable

      SHARD_BATCH_SIZE_FOR_REENQUEUE = 5

      def initialize(collection_class:, queue_shard_count:)
        @collection_class = collection_class
        @queue_shard_count = queue_shard_count.to_i
      end

      def execute
        valid, error = validate_prerequisites
        return ServiceResponse.error(message: error) unless valid

        previous_queue_shard_count = collection_class.queue.number_of_shards

        if queue_shard_count == previous_queue_shard_count
          return ServiceResponse.success(
            payload: {
              updated: false,
              message: 'The queue_shard_count value is the same as the current one.'
            }
          )
        end

        reenqueued_shards = update_queue_shard_count(previous_queue_shard_count)
        ServiceResponse.success(payload: { updated: true, reenqueued_shards: reenqueued_shards })
      end

      private

      attr_reader :collection_class, :queue_shard_count

      def validate_prerequisites
        return [false, "indexing is disabled"] unless ::ActiveContext.indexing?
        return [false, "queue_shard_count must be a positive integer"] unless queue_shard_count > 0
        return [false, "collection_record not found"] if collection_record.blank?

        if collection_class.queue.limit_throughput?
          return [
            false,
            "this collection's queue throughput is rate limited, " \
              "you cannot update the queue_shard_count"
          ]
        end

        if reenqueue_orphaned_refs_tasks_present?
          return [false, "shard rebalancing in progress, please try again later"]
        end

        [true, nil]
      end

      def reenqueue_orphaned_refs_tasks_present?
        ::Ai::ActiveContext::Task.with_active_connection.pending_or_in_progress.by_name(
          ::Ai::ActiveContext::Tasks::ReenqueueOrphanedRefs.name
        ).exists?
      end

      def update_queue_shard_count(previous_queue_shard_count)
        ApplicationRecord.transaction do
          collection_record.update_options!(queue_shard_count: queue_shard_count)

          # If the new queue_shard_count is greater than the previous queue_shard_count
          # there will be no orphaned queues
          if queue_shard_count > previous_queue_shard_count
            log_queue_shard_count_update(previous_queue_shard_count)
            next []
          end

          reenqueued_shards = create_reenqueue_orphaned_refs_tasks(previous_queue_shard_count)
          log_queue_shard_count_update(previous_queue_shard_count, reenqueued_shards)

          reenqueued_shards
        end
      end

      def create_reenqueue_orphaned_refs_tasks(previous_queue_shard_count)
        reenqueued_shards = []

        orphaned_shards = (queue_shard_count...previous_queue_shard_count).to_a
        orphaned_shards.each_slice(SHARD_BATCH_SIZE_FOR_REENQUEUE) do |sliced_shards|
          TaskService.new.create_task(
            ::Ai::ActiveContext::Tasks::ReenqueueOrphanedRefs,
            params: orphaned_queue_task_params(sliced_shards)
          )

          reenqueued_shards += sliced_shards
        end

        reenqueued_shards
      end

      def orphaned_queue_task_params(shards)
        { 'collection' => collection_name, 'queue_shards' => shards }
      end

      def collection_record
        collection_class.collection_record
      end
      strong_memoize_attr :collection_record

      def collection_name
        collection_record.name_without_prefix
      end
      strong_memoize_attr :collection_name

      def log_queue_shard_count_update(previous_count, reenqueued_shards = [])
        logger.info(
          build_structured_payload(
            message: "queue_shard_count updated",
            collection: collection_name,
            old_value: previous_count,
            new_value: queue_shard_count,
            reenqueued_shards: reenqueued_shards
          )
        )
      end
    end
  end
end
