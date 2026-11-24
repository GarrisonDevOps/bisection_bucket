# frozen_string_literal: true

module Geo
  module BlobReplicatorStrategy
    extend ActiveSupport::Concern

    # Matches the check constraint on the blob_path column of the Geo registry tables
    BLOB_PATH_MAX_LENGTH = 1024

    include ::Geo::VerifiableReplicator
    include EE::GeoHelper # rubocop: disable Cop/InjectEnterpriseEditionModule -- not an EE extension of this module

    included do
      event ::Geo::ReplicatorEvents::EVENT_CREATED
      event ::Geo::ReplicatorEvents::EVENT_DELETED
    end

    class_methods do
      def sync_timeout
        ::GeoNode.current_node.blob_download_timeout.seconds
      end

      def data_type
        'blob'
      end

      def data_type_title
        _('Blob')
      end

      def data_type_sort_order
        1
      end

      # Model records for a bulk blob location computation, with the preloads it needs
      def blob_location_records(model_ids)
        scope = model.primary_key_in(model_ids)
        preloads = blob_location_preloads

        preloads.empty? ? scope : scope.preload(*preloads)
      end

      # Associations to preload on model records before computing their blob location in
      # bulk, for uploaders whose path reads an association. Overridden by replicators that need it.
      #
      # @return [Array] argument for ActiveRecord's preload
      def blob_location_preloads
        []
      end

      def bulk_create_delete_events_async(deleted_records)
        return unless deleted_records.any?
        raise 'This method can only be called for a child class of Gitlab::Geo::Replicator' if replicable_name.nil?
        return unless ::Geo::EventStore.can_create_event?

        deleted_record_details = []

        events = deleted_records.map do |record|
          deleted_record_details << [replicable_name, record[:model_record_id], record[:blob_path]]

          raise 'model_record_id can not be nil' if record[:model_record_id].nil?

          {
            replicable_name: replicable_name,
            event_name: ::Geo::ReplicatorEvents::EVENT_DELETED,
            payload: {
              model_record_id: record[:model_record_id],
              blob_path: record[:blob_path].to_s,
              uploader_class: record[:uploader_class],
              correlation_id: Labkit::Correlation::CorrelationId.current_id
            },
            created_at: Time.current.to_s
          }.deep_transform_keys(&:to_s)
        end

        log_info('Bulk delete of: ', details: deleted_record_details)

        ::Geo::BatchEventCreateWorker.perform_async(events)
      end
    end

    # Called by Gitlab::Geo::Replicator#consume
    def consume_event_created(**_params)
      with_record_not_found_handling do
        next unless in_replicables_for_current_secondary?

        # Race condition mitigation for mutable types.
        #
        # Within a created event, we know that the source primary has changed. If a
        # sync is currently running, then *this* sync will be deduplicated (exit
        # early due to not being able to take the exclusive lease). In that case,
        # moving the registry to "pending" will block the currently running sync
        # from moving it to "synced". The running sync will then reschedule
        # itself to ensure a sync begins *after* the last known change to the
        # source primary. See `ReplicableRegistry#mark_synced_atomically`.
        #
        # We avoid saving when unpersisted since this should only occur if a
        # resource was just created but not yet replicated. And all saves after
        # the first one will raise the error `ActiveRecord::RecordNotUnique` anyway.
        registry.pending! if registry.persisted? && mutable?

        download
      end
    end

    def sync
      with_record_not_found_handling do
        next unless in_replicables_for_current_secondary?

        ::Geo::BlobDownloadService.new(replicator: self).execute
      end
    end
    alias_method :download, :sync # Backwards compatible with old docs, keep at least till 17.6

    def enqueue_sync
      Geo::EventWorker.perform_async(
        replicable_name,
        ::Geo::ReplicatorEvents::EVENT_CREATED,
        event_params
      )
    end

    # Schedules a verification job after a model record is created/updated
    #
    # Called by Gitlab::Geo::Replicator#geo_handle_after_(create|update)
    def after_verifiable_update
      verify_async if should_primary_verify_after_save?
    end

    # Called by Gitlab::Geo::Replicator#consume
    # Keep in mind that in_replicables_for_current_secondary? is not called here
    # This is because delete event should be handled by all the nodes
    # even if they're out of scope
    def consume_event_deleted(**params)
      replicate_destroy(params)
    end

    # Return the carrierwave uploader instance scoped to current model
    #
    # @abstract
    # @return [Carrierwave::Uploader]
    def carrierwave_uploader
      raise NotImplementedError
    end

    # Return the absolute path to locally stored file
    #
    # @return [String] File path
    def blob_path
      carrierwave_uploader.path
    end

    def replicate_destroy(event_data)
      location = event_data[:blob_path].present? ? event_data : registry_location_params

      ::Geo::FileRegistryRemovalService.new(
        replicable_name,
        model_record_id,
        removed_blob_path(location[:uploader_class], location[:blob_path]),
        location[:uploader_class]
      ).execute
    end

    # Returns the blob location stored on the registry, or {} when it is missing or unsafe to use
    #
    # @return [Hash] { blob_path:, uploader_class: } or {}
    def registry_location_params
      return {} unless ::Feature.enabled?(:geo_blob_removal_uses_registry_location, :instance)

      # The service builds the path from the live model, which also covers selective sync.
      return {} if model.primary_key_in(model_record_id).exists?

      # `registry` runs a query on every call, so read it once and take every field from the same row.
      stored_registry = registry
      return {} unless stored_registry.has_attribute?(:blob_path) && stored_registry.blob_path.present?

      uploader_class = stored_uploader_class(stored_registry)
      return {} if uploader_class.blank?
      return {} if stored_location_in_use?(stored_registry.blob_path, uploader_class)

      { blob_path: stored_registry.blob_path, uploader_class: uploader_class }
    end

    # Whether a live record still uses this location, so removing the file would delete its data.
    # False by default, because most blob paths include the record ID and are never reused.
    #
    # @return [Boolean]
    def blob_location_in_use?(_blob_path, _uploader_class)
      false
    end

    # Uploader class name for a stored location, resolved without a model record
    #
    # @return [String]
    def stored_uploader_class(_registry)
      model.uploaders.fetch(:file).to_s
    end

    def removed_blob_path(uploader_class, path)
      return unless path.present?
      # Backward compatibility check. Remove in 15.x
      return path if uploader_class.nil?

      File.join(uploader_class.constantize.root, path)
    end

    # Returns a checksum for the local files and file size for remote ones
    #
    # @return [String] SHA256 hash or file size
    def calculate_checksum
      raise not_checksummable_error unless checksummable?

      if carrierwave_uploader.file_storage?
        model.sha256_hexdigest(blob_path)
      else
        format_file_size_for_checksum(carrierwave_uploader.file.size.to_s)
      end
    end

    # Returns whether the file exists on disk or in remote storage
    #
    # Does a hard check because we are doing these checks for replication or
    # verification purposes, so we should not just trust the data in the DB if
    # we don't absolutely have to.
    #
    # @return [Boolean] whether the file exists on disk or in remote storage
    def resource_exists?
      carrierwave_uploader.file&.exists?
    rescue Excon::Error::Forbidden => e
      # AWS S3 returns 403 Forbidden instead of 404 when the file does not
      # exist and the IAM role lacks the ListBucket permission. Treat this as
      # "does not exist" so that verification/checksumming is handled gracefully.
      # See: https://docs.gitlab.com/administration/geo/replication/troubleshooting/synchronization_verification/
      Gitlab::ErrorTracking.track_exception(
        e,
        replicable_name: replicable_name,
        model_record_id: model_record_id
      )
      log_warning('Received Forbidden error when checking if resource exists in object storage. ' \
        'Ensure the IAM role has the ListBucket permission. Treating as not found.',
        replicable_name: replicable_name,
        model_record_id: model_record_id)
      false
    end

    def deleted_params
      {
        model_record_id: model_record_id,
        uploader_class: carrierwave_uploader.class.to_s,
        blob_path: carrierwave_uploader.relative_path
      }
    end

    # The location to store on the registry, or nil values when it is missing or unusable.
    # Never raises: a path over the column limit is logged and an error is tracked.
    #
    # @return [Hash] { blob_path:, uploader_class: }
    def registry_blob_location
      location = deleted_params
      blob_path = location[:blob_path].to_s.presence

      if blob_path && blob_path.length > BLOB_PATH_MAX_LENGTH
        log_warning(
          "Blob path too long to record",
          replicable_name: replicable_name,
          model_record_id: model_record_id,
          path_length: blob_path.length
        )
        blob_path = nil
      end

      { blob_path: blob_path, uploader_class: blob_path && location[:uploader_class] }
    rescue StandardError => error
      Gitlab::ErrorTracking.track_exception(
        error,
        replicable_name: replicable_name,
        model_record_id: model_record_id
      )
      { blob_path: nil, uploader_class: nil }
    end

    # Return whether it's immutable
    #
    # @return [Boolean] whether the replicable is immutable
    def immutable?
      # Most blobs are supposed to be immutable.
      # Override this in your specific Replicator class if needed.
      true
    end

    private

    # Object storage keys start with the bucket prefix, but the columns the in-use checks match never include it.
    # A local path can start with the prefix too, so a match with or without it counts.
    def stored_location_in_use?(blob_path, uploader_class)
      bucket_prefix = uploader_class.constantize.object_store_options.bucket_prefix
      paths = [blob_path]
      paths << blob_path.delete_prefix("#{bucket_prefix}/") if bucket_prefix.present?

      paths.uniq.any? { |path| blob_location_in_use?(path, uploader_class) }
    end

    def not_checksummable_error
      unless model_record.in_verifiables?
        return Geo::Errors::ReplicableExcludedFromVerificationError.new(
          model_class: model_record.class.name,
          model_record_id: model_record_id
        )
      end

      Geo::Errors::ReplicableDoesNotExistError.new(
        file_path: blob_path
      )
    end
  end
end
