# frozen_string_literal: true

module ClickHouse
  class CiFinishedBuildsSyncCronWorker
    include ApplicationWorker

    version 2

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :fleet_visibility
    tags :clickhouse

    def perform(*args)
      return unless job_version == 2
      return unless ::ClickHouse::DataIngestion::CiFinishedBuildsSyncService.enabled?

      enqueue_workers(args.first || 1)

      nil
    end

    private

    def enqueue_workers(total_workers)
      total_workers.times do |worker_index|
        CiFinishedBuildsSyncWorker.perform_async(worker_index, total_workers)
      end
    end
  end
end
