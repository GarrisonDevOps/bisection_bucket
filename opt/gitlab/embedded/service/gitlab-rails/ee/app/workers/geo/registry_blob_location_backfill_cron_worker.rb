# frozen_string_literal: true

module Geo
  # Starts the blob location backfill for every blob replicator that is not done yet.
  class RegistryBlobLocationBackfillCronWorker
    include ApplicationWorker

    data_consistency :always # rubocop:disable SidekiqLoadBalancing/WorkerDataConsistency -- Geo registries live in the tracking database

    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- No user, project or namespace context

    feature_category :geo_replication

    idempotent!

    def perform
      return unless Gitlab::Geo.secondary?

      Gitlab::Geo.blob_replicator_classes.each do |replicator_class|
        next unless replicator_class.registry_class.column_names.include?('blob_path')

        replicable_name = replicator_class.replicable_name
        next if Gitlab::Geo::RegistryBlobLocationBackfillCursor.new(replicable_name).done?

        Geo::RegistryBlobLocationBackfillWorker.perform_with_capacity(replicable_name)
      end
    end
  end
end
