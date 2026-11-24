# frozen_string_literal: true

class SetDevQueueShardCount < ActiveContext::Migration[1.0]
  milestone '19.5'

  # Sets the number of parallel shards that can be processed at a time for a single queue.
  # Setting this to a higher number than the default of `1` speeds up
  # embeddings indexing in local development setups.
  # This value is within GDK's default of 20 max concurrent Sidekiq jobs.
  QUEUE_SHARD_COUNT = 4

  def migrate!
    collection_record = collection.collection_record
    return if collection_record.queue_shard_count == QUEUE_SHARD_COUNT

    collection_record.update_options!(queue_shard_count: QUEUE_SHARD_COUNT)
  end

  def skip?
    !Rails.env.development?
  end

  def collection
    Ai::ActiveContext::Collections::Code
  end
end
