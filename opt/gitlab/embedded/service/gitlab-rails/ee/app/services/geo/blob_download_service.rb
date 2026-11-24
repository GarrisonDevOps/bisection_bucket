# frozen_string_literal: true

module Geo
  class BlobDownloadService
    include ExclusiveLeaseGuard
    include Gitlab::Geo::LogHelpers

    # Initialize a new blob downloader service
    #
    # @param [Gitlab::Geo::Replicator] replicator instance
    def initialize(replicator:)
      @replicator = replicator
    end

    # Downloads a blob from the primary and places it where it should be. And
    # records sync status in Registry.
    #
    # Exits early if another instance is running for the same replicable model.
    #
    # @return [Boolean] true if synced, false if not
    def execute
      try_obtain_lease do
        start_time = Time.current
        sync_successful = false

        registry.start!

        begin
          downloader = ::Gitlab::Geo::Replication::BlobDownloader.new(replicator: @replicator)
          download_result = downloader.execute

          sync_successful = process_download_result(download_result)
        rescue StandardError => error
          # if an exception raises here, it will be stuck in "started" state until
          # the cleanup process forces it to failed much later.
          # To avoid that, catch the error, mark sync as
          # failed, and re-raise the exception here.
          registry.failed!(
            message: "Error while attempting to sync",
            error: error
          )
          track_exception(error)
        ensure
          # make sure we're not stuck in a started state still
          if registry.started?
            sync_successful ? registry.synced! : registry.failed!(message: "Unknown system error")
          end
        end

        log_download(sync_successful, download_result, start_time)

        sync_successful
      end
    end

    private

    def registry
      @registry ||= @replicator.registry
    end

    def process_download_result(download_result)
      if download_result.success
        record_blob_location
        registry.synced!
        return true
      end

      message = download_result.reason
      error = download_result.extra_details&.delete(:error)

      track_exception(error) if error

      registry.failed!(message: message, error: error, missing_on_primary: download_result.primary_missing_file)

      false
    end

    # This never fails a sync. On any problem it stores nil rather than keeping a value
    # from an earlier sync, which could point at a different file.
    def record_blob_location
      return unless registry.has_attribute?(:blob_path)

      location = @replicator.registry_blob_location

      registry.blob_path = location[:blob_path]
      registry.uploader_class = location[:uploader_class] if registry.has_attribute?(:uploader_class)
    end

    def log_download(mark_as_synced, download_result, start_time)
      metadata = {
        replicable_name: @replicator.replicable_name,
        model_record_id: @replicator.model_record_id,
        mark_as_synced: mark_as_synced,
        download_success: download_result&.success || false,
        bytes_downloaded: download_result&.bytes_downloaded || 0,
        primary_missing_file: download_result&.primary_missing_file || false,
        download_time_s: (Time.current - start_time).to_f.round(3),
        reason: download_result&.reason
      }
      metadata.merge!(download_result.extra_details) if download_result&.extra_details

      log_warning("Blob download", metadata)
    end

    def track_exception(exception)
      Gitlab::ErrorTracking.track_exception(
        exception,
        replicable_name: @replicator.replicable_name,
        model_record_id: @replicator.model_record_id
      )
    end

    def lease_key
      @lease_key ||= "#{self.class.name.underscore}:#{@replicator.replicable_name}:#{@replicator.model_record.id}"
    end

    def lease_timeout
      @replicator.class.sync_timeout
    end
  end
end
