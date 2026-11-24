# frozen_string_literal: true

module Geo
  class BulkRegistryResyncWorker
    include ApplicationWorker
    include Gitlab::Geo::LogHelpers

    idempotent!
    data_consistency :sticky
    deduplicate :until_executed, ttl: 1.hour

    feature_category :geo_replication

    def perform(registry_class_name, worker_params = {})
      result = Geo::BulkRegistryResyncService.new(registry_class_name, worker_params).execute

      log_extra_metadata_on_done(:result, { status: result.payload[:status] })
    end
  end
end
