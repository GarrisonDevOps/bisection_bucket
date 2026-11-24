# frozen_string_literal: true

module PackageMetadata # rubocop:disable Gitlab/BoundedContexts -- Existing context
  # Security advisories over the v3 contract, which is what PDS serves. V3SyncService
  # owns the run; this class names the dataset and supplies its ingestion pieces.
  class AdvisoryV3SyncService < V3SyncService
    # The worker takes its lease from this once it routes here, so the two cannot
    # drift. max_sync_duration stays below it so a run stops before the lease expires.
    MAX_LEASE_LENGTH = 22.minutes

    class << self
      def data_type
        'advisories'
      end

      def fabricator_class
        DataObjectFabricator
      end

      def ingestion_service
        Ingestion::Advisory::IngestionService
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
        'advisory_sync'
      end
    end

    private

    # Tells snapshot-triggered scans from delta ones in the Queued scan for advisory log.
    def ingest(data, file)
      self.class.ingestion_service.execute(data, sync_mode: file_mode(file))
    end
  end
end
