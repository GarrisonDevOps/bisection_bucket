# frozen_string_literal: true

module Geo
  # Fills the stored blob location of registries that were synced before it was recorded.
  # Each call claims and processes one range of registry IDs; the replicator is done
  # once a claimed range starts above its highest registry ID.
  class RegistryBlobLocationBackfillService
    include Gitlab::Geo::LogHelpers

    # @param [Class] replicator_class a blob replicator class
    # @param [Integer] batch_size number of registry IDs per range
    def initialize(replicator_class, batch_size:)
      @replicator_class = replicator_class
      @batch_size = batch_size
    end

    def execute
      return if cursor.done?

      max_id = registry_class.maximum(:id).to_i
      range = cursor.claim_range(batch_size)

      if range.begin > max_id
        cursor.mark_done!
        log_info("Registry blob location backfill complete", replicable_name: replicable_name)
        return
      end

      updated = begin
        backfill(range)
      rescue StandardError => error
        log_error(
          "Registry blob location backfill batch failed", error,
          replicable_name: replicable_name, first_id: range.begin, last_id: range.end
        )
        raise
      end

      log_debug(
        "Registry blob location backfill batch",
        replicable_name: replicable_name, first_id: range.begin, last_id: range.end, updated_count: updated
      )
    end

    private

    attr_reader :replicator_class, :batch_size

    delegate :registry_class, :replicable_name, to: :replicator_class

    def cursor
      @cursor ||= Gitlab::Geo::RegistryBlobLocationBackfillCursor.new(replicable_name)
    end

    def backfill(range)
      registry_ids_by_model_id = registry_class.synced_without_blob_location(range)
      return 0 if registry_ids_by_model_id.empty?

      locations = locations_for(registry_ids_by_model_id)

      registry_class.fill_missing_blob_locations(locations)
    end

    # Registries whose model is gone are skipped.
    def locations_for(registry_ids_by_model_id)
      replicator_class.blob_location_records(registry_ids_by_model_id.keys).filter_map do |record|
        location = replicator_class.new(model_record: record).registry_blob_location
        next unless location[:blob_path]

        { id: registry_ids_by_model_id.fetch(record.id), **location }
      end
    end
  end
end
