# frozen_string_literal: true

module Geo
  # Fail sync for records which started syncing a long time ago
  class SyncTimeoutCronWorker
    include ApplicationWorker

    data_consistency :always
    include ::Gitlab::Geo::LogHelpers

    # This worker does not perform work scoped to a context
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext

    idempotent!
    sidekiq_options retry: false
    feature_category :geo_replication

    def perform
      return unless ::Gitlab::Geo.secondary_or_org_migration_target?

      Gitlab::Geo.replication_enabled_replicator_classes.each(&:fail_sync_timeouts)
    end
  end
end
