# frozen_string_literal: true

module PackageMetadata # rubocop:disable Gitlab/BoundedContexts -- Existing context
  # Package licenses over the v3 contract, which is what PDS supports.
  class LicenseV3SyncService < V3SyncService
    # Named because LicensesSyncWorker::LEASE_TIMEOUT must match it; max_sync_duration
    # stays below it so the sync stops before the lease expires. Both are sized so one
    # archive fits in a run: a run checkpoints only on crossing into the next archive,
    # so an archive that outlasts the budget never progresses.
    MAX_LEASE_LENGTH = 22.minutes

    class << self
      def data_type
        'licenses'
      end

      def fabricator_class
        DataObjectFabricator
      end

      def ingestion_service
        Ingestion::CompressedPackage::IngestionService
      end

      def max_lease_length
        MAX_LEASE_LENGTH
      end

      def max_sync_duration
        20.minutes
      end

      def ingest_slice_size
        1_000
      end

      def throttle_rate
        0.25.seconds
      end

      def log_event
        'license_sync'
      end
    end
  end
end
