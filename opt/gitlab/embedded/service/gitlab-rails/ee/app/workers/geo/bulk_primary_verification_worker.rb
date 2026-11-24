# frozen_string_literal: true

module Geo
  class BulkPrimaryVerificationWorker
    include ApplicationWorker
    include Gitlab::Geo::LogHelpers

    idempotent!
    data_consistency :sticky
    deduplicate :until_executed, ttl: 1.hour

    feature_category :geo_replication

    def perform(model_name, worker_params = {})
      result = Geo::BulkPrimaryVerificationService.new(model_name, worker_params).execute

      log_extra_metadata_on_done(:result, { status: result.payload[:status] })
    end
  end
end
