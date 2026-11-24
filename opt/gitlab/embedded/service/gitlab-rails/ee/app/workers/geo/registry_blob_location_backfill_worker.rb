# frozen_string_literal: true

module Geo
  # Backfills blob locations on registries synced before Geo::BlobDownloadService recorded them.
  class RegistryBlobLocationBackfillWorker
    include ApplicationWorker

    data_consistency :always # rubocop:disable SidekiqLoadBalancing/WorkerDataConsistency -- Geo registries live in the tracking database

    sidekiq_options retry: false
    include GeoQueue
    include LimitedCapacity::Worker

    BATCH_SIZE = 250

    idempotent!
    loggable_arguments 0

    # Errors propagate so LimitedCapacity::Worker does not re-enqueue: a persistent failure
    # then waits for the next cron run instead of looping through the table.
    def perform_work(replicable_name)
      Geo::RegistryBlobLocationBackfillService
        .new(replicator_class_for(replicable_name), batch_size: BATCH_SIZE)
        .execute
    end

    # Memoized because LimitedCapacity::Worker calls it twice after each batch.
    def remaining_work_count(replicable_name)
      @remaining_work_count ||= estimated_batch_count(replicable_name)
    end

    def max_running_jobs
      node = Gitlab::Geo.current_node
      return 0 unless node

      capacity = node.files_max_capacity
      return 0 if capacity <= 0

      [capacity / 2, 1].max
    end

    private

    # Estimated number of batches left, at least one until a batch has marked the replicator done.
    def estimated_batch_count(replicable_name)
      cursor = Gitlab::Geo::RegistryBlobLocationBackfillCursor.new(replicable_name)
      return 0 if cursor.done?

      max_id = replicator_class_for(replicable_name).registry_class.maximum(:id).to_i
      batches = ((max_id - cursor.position) / BATCH_SIZE.to_f).ceil

      [[batches, 1].max, max_running_jobs].min
    end

    def replicator_class_for(replicable_name)
      ::Gitlab::Geo::Replicator.for_replicable_name(replicable_name)
    end
  end
end
