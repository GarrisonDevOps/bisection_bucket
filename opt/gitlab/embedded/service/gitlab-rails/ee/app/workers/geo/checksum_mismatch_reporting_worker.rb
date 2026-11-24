# frozen_string_literal: true

module Geo
  class ChecksumMismatchReportingWorker
    include ApplicationWorker
    include Gitlab::Geo::LogHelpers
    # rubocop:disable Scalability/CronWorkerContext -- This worker does not perform work scoped to a context
    include CronjobQueue

    # rubocop:enable Scalability/CronWorkerContext

    idempotent!
    worker_has_external_dependencies!
    data_consistency :sticky
    feature_category :geo_replication

    def perform
      return unless Gitlab::Geo.secondary?
      return unless Feature.enabled?(:geo_self_heal_checksum_mismatch, :instance, type: :ops)

      Geo::ChecksumMismatchReportingService.new(Gitlab::Geo.current_node).execute
    end
  end
end
