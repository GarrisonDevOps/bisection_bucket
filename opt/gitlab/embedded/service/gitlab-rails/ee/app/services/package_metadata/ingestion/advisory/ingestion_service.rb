# frozen_string_literal: true

module PackageMetadata
  module Ingestion
    module Advisory
      class IngestionService
        PUBLISHED_ADVISORY_INTERVAL = 14.days

        def self.execute(import_data, sync_mode: nil)
          new(import_data, sync_mode: sync_mode).execute
        end

        def initialize(import_data, sync_mode: nil)
          @sync_mode = sync_mode
          @import_data = filter_false_positives(import_data)
          @advisory_map = {}
        end

        # V3SyncService reads this as "was the slice persisted" to decide whether to
        # advance a checkpoint, so return a Boolean rather than publish!'s value.
        def execute
          ApplicationRecord.transaction do
            upsert_advisory_data
            upsert_affected_package_data
          end
          publish!

          true
        end

        private

        def upsert_advisory_data
          @advisory_map = AdvisoryIngestionTask.execute(import_data)
        end

        def upsert_affected_package_data
          AffectedPackageIngestionTask.execute(import_data, advisory_map)
        end

        def publish!
          publishable_advisories.each do |data_object|
            source_xid = data_object.source_xid
            advisory_xid = data_object.advisory_xid

            log_queued_advisory_scan(source_xid, advisory_xid)

            Gitlab::EventStore.publish(
              PackageMetadata::IngestedAdvisoryEvent.new(data: { advisory_id: data_object.id }))
          end
        end

        def publishable_advisories
          advisory_map.values.select do |data_object|
            published_time = data_object.published_date.to_time
            now - published_time.in_time_zone(Time.zone) < PUBLISHED_ADVISORY_INTERVAL
          end
        end

        def now
          @now ||= Time.zone.now
        end

        attr_reader :import_data, :advisory_map, :sync_mode

        def filter_false_positives(import_data)
          import_data.reject do |data_object|
            next false unless data_object.false_positive?

            log_skipped_false_positive(data_object.source_xid, data_object.advisory_xid)
            true
          end
        end

        def log_queued_advisory_scan(source_xid, advisory_xid)
          fields = { message: 'Queued scan for advisory', source_xid: source_xid, advisory_xid: advisory_xid }
          fields[:sync_mode] = sync_mode if sync_mode
          Gitlab::AppJsonLogger.info(**fields)
        end

        def log_skipped_false_positive(source_xid, advisory_xid)
          Gitlab::AppJsonLogger.info(message: 'Skipped false positive advisory',
            source_xid: source_xid, advisory_xid: advisory_xid)
        end
      end
    end
  end
end
