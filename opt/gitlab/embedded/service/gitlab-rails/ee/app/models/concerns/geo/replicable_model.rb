# frozen_string_literal: true

module Geo
  module ReplicableModel
    extend ActiveSupport::Concern
    include Checksummable
    include HasReplicator
    include Orderable
    include ::Gitlab::Geo::LogHelpers
    include ::Gitlab::Utils::StrongMemoize

    included do
      # If this hook turns out not to apply to all Models, perhaps we should extract a `ReplicableBlobModel`
      after_create_commit :geo_create_event!
      # Inside the destroy transaction where possible, so the event is atomic with the delete.
      # A model in another database (CI) waits for the commit: writing geo_events inside its
      # transaction would modify two databases at once.
      after_destroy :geo_destroy_event!, unless: :geo_events_in_another_database?
      # Read in the transaction: blob deleted_params need the file path, which CarrierWave's
      # own after_commit hook clears.
      after_destroy :geo_capture_deleted_params!, if: :geo_events_in_another_database?
      after_destroy_commit :geo_destroy_event!, if: :geo_events_in_another_database?

      delegate :geo_handle_after_create, to: :replicator
      delegate :geo_handle_after_destroy, to: :replicator
      delegate :geo_handle_after_update, to: :replicator

      # These scopes are intended to be overridden as needed
      scope :available_replicables, -> { all }

      # On primary, `verifiables` are records that can be checksummed and/or are replicable.
      # On secondary, `verifiables` are records that have already been replicated
      # and (ideally) have been checksummed on the primary
      scope :verifiables, ->(primary_key_in = nil) do
        node = ::GeoNode.current_node

        replicables = available_replicables
        replicables = replicables.merge(object_storage_scope(node)) if object_storable?

        if ::Gitlab::Geo.org_mover_extend_selective_sync_to_primary_checksumming?
          replicables.merge(selective_sync_scope(node, primary_key_in: primary_key_in, replicables: replicables))
        else
          primary_key_in ? replicables.primary_key_in(primary_key_in) : replicables
        end
      end

      # The method is tested but undercoverage task doesn't detect it.
      def geo_create_event!
        replicator.geo_handle_after_create if replicator.respond_to?(:geo_handle_after_create)
      rescue StandardError => err
        log_error("Geo replicator after_create_commit failed", err)
      end

      def geo_destroy_event!
        return unless replicator.respond_to?(:geo_handle_after_destroy)

        replicator.geo_handle_after_destroy(@geo_deleted_params)
      rescue StandardError => err
        log_error("Geo replicator after_destroy failed", err)
      end

      def geo_capture_deleted_params!
        return unless ::Gitlab::Geo.primary? && replicator.respond_to?(:geo_handle_after_destroy)

        @geo_deleted_params = replicator.deleted_params
      rescue StandardError => err
        log_error("Geo replicator could not read deleted params", err)
      end

      def geo_events_in_another_database?
        # Use gitlab_schema, not the physical connection: in single-database mode
        # the connections are equal but writing geo_events in this model's transaction
        # is still a cross-schema (gitlab_ci + gitlab_main_cell_local) modification.
        !::Gitlab::Database::GitlabSchema.cross_transactions_allowed?(
          [self.class.table_name, ::Geo::Event.table_name]
        )
      end
    end

    class_methods do
      # @param primary_key_in [Range, Replicable] arg to pass to primary_key_in scope
      # @return [ActiveRecord::Relation<Replicable>] everything that should be synced to this
      #         node, restricted by primary key
      def replicables_for_current_secondary(primary_key_in)
        node = ::Gitlab::Geo.current_node

        replicables = available_replicables
        replicables = replicables.merge(object_storage_scope(node)) if object_storable?

        replicables
          .merge(selective_sync_scope(node, primary_key_in: primary_key_in, replicables: replicables))
      end

      # @return [ActiveRecord::Relation<Replicable>] scope observing object storage settings of the given node
      def object_storage_scope(node)
        return all unless object_storable?
        return all if node.primary? && Feature.enabled?(:geo_object_storage_verification)
        return all if node.secondary_or_org_migration_target? && node.sync_object_storage?

        with_files_stored_locally
      end

      # @param model_type [String, nil] value for the LIST partition key of `uploads`; nil for
      #        tables not partitioned by model_type.
      # @param partition_id [Integer, nil] value for the partition key of `p_ci_job_artifacts`;
      #        nil for tables not partitioned by partition_id.
      # @return [ActiveRecord::Relation<Replicable>] object_storage_scope(node) restricted to
      #         primary_key. A supplied partition key prunes partitioned tables (e.g.
      #         p_ci_job_artifacts, uploads) to a single partition instead of the planner
      #         considering an Append across all of them.
      def object_storage_scope_for(node, primary_key, model_type: nil, partition_id: nil)
        object_storage_scope(node)
          .id_in(primary_key)
          .where({ model_type: model_type, partition_id: partition_id }.compact)
      end

      def object_storable?
        respond_to?(:with_files_stored_locally)
      end

      # @return [ActiveRecord::Relation<Replicable>] scope observing selective sync settings of the given node
      def selective_sync_scope(node, **params)
        raise NotImplementedError, "#{name} does not implement #{__method__}"
      end
    end

    # @return [String] human-readable title. E.g. "Package File"
    # Override in each model that includes this concern
    def self.replicable_title
      raise NotImplementedError
    end

    # @return [String] pluralized human-readable title. E.g. "Package Files"
    # Override in each model that includes this concern
    def self.replicable_title_plural
      raise NotImplementedError
    end

    def in_replicables_for_current_secondary?
      self.class.replicables_for_current_secondary(self).exists?
    end
    strong_memoize_attr :in_replicables_for_current_secondary?
  end
end
