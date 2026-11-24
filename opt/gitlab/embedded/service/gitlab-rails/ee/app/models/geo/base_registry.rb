# frozen_string_literal: true

module Geo
  class BaseRegistry < Geo::TrackingBase
    include BulkInsertSafe

    self.abstract_class = true

    include GlobalID::Identification

    def self.pluck_model_ids_in_range(range)
      where(model_foreign_key => range).pluck(model_foreign_key)
    end

    def self.model_id_in(ids)
      where(model_foreign_key => ids)
    end

    def self.model_id_not_in(ids)
      where.not(model_foreign_key => ids)
    end

    def self.model_updated_last
      :updated_at
    end

    def self.ordered_by_id
      order(:id)
    end

    def self.ordered_by(method)
      case method.to_s
      when 'id_desc'
        order(id: :desc)
      when 'verified_at_asc'
        order(verified_at: :asc)
      when 'verified_at_desc'
        order(verified_at: :desc)
      when 'last_synced_at_asc'
        order(last_synced_at: :asc)
      when 'last_synced_at_desc'
        order(last_synced_at: :desc)
      else
        ordered_by_id
      end
    end

    def self.insert_for_model_ids(ids)
      records = ids.map do |id|
        new(model_foreign_key => id, created_at: Time.zone.now)
      end

      bulk_insert!(records, returns: :ids, skip_duplicates: true)
    end

    def self.delete_for_model_ids(ids)
      ids.map do |id|
        delete_worker_class.perform_async(replicator_class.replicable_name, id)
      end
    end

    def self.delete_worker_class
      ::Geo::DestroyWorker
    end

    def self.replicator_class
      model_class.replicator_class
    end

    def self.find_registry_differences(range)
      model_primary_key = model_class.primary_key.to_sym

      source_ids = model_class
                    .replicables_for_current_secondary(range)
                    .pluck(model_class.arel_table[model_primary_key])

      tracked_ids = pluck_model_ids_in_range(range)

      untracked_ids = source_ids - tracked_ids
      unused_tracked_ids = tracked_ids - source_ids

      [untracked_ids, unused_tracked_ids]
    end

    def self.find_registries_pending(batch_size:, except_ids: [])
      pending
        .model_id_not_in(except_ids)
        .limit(batch_size)
    end

    def self.find_registries_needs_sync_again(batch_size:, except_ids: [])
      needs_sync_again
        .model_id_not_in(except_ids)
        .limit(batch_size)
    end

    def self.has_create_events?
      true
    end

    # Method to generate a GraphQL enum key based on registry class.
    def self.graphql_enum_key
      to_s.gsub('Geo::', '').underscore.upcase
    end

    # Search for a list of records associated with registries,
    # based on the query given in `query`.
    #
    # @param [String] query term that will search over replicable registries
    def self.with_search(query)
      return all if query.empty?

      where(model_foreign_key => model_class.search(query).limit(1000).pluck_primary_key)
    end

    def model_record_id
      read_attribute(self.class.model_foreign_key)
    end
  end
end
