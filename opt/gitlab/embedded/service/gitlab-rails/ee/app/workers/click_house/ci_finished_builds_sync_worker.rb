# frozen_string_literal: true

module ClickHouse
  class CiFinishedBuildsSyncWorker
    include ApplicationWorker
    include ClickHouseWorker

    idempotent!
    data_consistency :sticky
    urgency :throttled
    sidekiq_options retry: false
    feature_category :fleet_visibility
    tags :clickhouse

    def perform(worker_index = 0, total_workers = 1)
      response = ::ClickHouse::DataIngestion::CiFinishedBuildsSyncService.new(
        worker_index: worker_index, total_workers: total_workers
      ).execute

      result = response.success? ? response.payload : response.deconstruct_keys(%i[message reason])
      log_extra_metadata_on_done(:result, result)
    end
  end
end
