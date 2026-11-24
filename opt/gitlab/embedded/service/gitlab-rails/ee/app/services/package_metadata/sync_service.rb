# frozen_string_literal: true

module PackageMetadata
  class SyncService
    UnknownAdapterError = Class.new(StandardError)
    MAX_LEASE_LENGTH = 6.minutes
    # A run reads the stop signal only before a file, so it lasts the sync budget
    # plus one whole file. The lease is sized to outlast a file at the export's
    # size limit, and to expire before the next hourly run, because a Sidekiq
    # process that is killed rather than stopped never releases it.
    CVE_ENRICHMENT_MAX_LEASE_LENGTH = 55.minutes
    MAX_SYNC_DURATION = 4.minutes
    INGEST_SLICE_SIZE = 200
    THROTTLE_RATE = 0.75.seconds

    def self.execute(data_type:, lease:)
      signal = PackageMetadata::StopSignal.new(lease, max_lease_length(data_type), MAX_SYNC_DURATION)
      SyncConfiguration.configs_for(data_type).each do |sync_config|
        if signal.stop?
          break Gitlab::AppJsonLogger.debug(class: name,
            message: "Stop signal before sync of #{sync_config}")
        end

        new(sync_config, signal).execute
      end
    end

    def self.max_lease_length(data_type)
      data_type == 'cve_enrichment' ? CVE_ENRICHMENT_MAX_LEASE_LENGTH : MAX_LEASE_LENGTH
    end
    private_class_method :max_lease_length

    def initialize(sync_config, signal)
      @sync_config = sync_config
      @signal = signal
    end

    def execute
      connector.data_after(resume_point).each do |file|
        return log_stop_signal if signal.stop?

        Gitlab::AppJsonLogger.debug(class: self.class.name, message: "Evaluating data for #{sync_config}/#{file}")

        ingest_file(file)
        advance_checkpoint(file)
      end

      finish_full_sync
    end

    private

    def ingest_file(file)
      DataObjectFabricator.new(data_file: file, sync_config: sync_config)
        .each_slice(INGEST_SLICE_SIZE) do |data_objects|
          ingest(data_objects)
          throttle
        end
    end

    def log_stop_signal
      Gitlab::AppJsonLogger.debug(class: self.class.name,
        message: "Stop signal after checkpointing")
    end

    attr_accessor :sync_config, :signal

    def ingest(data)
      if sync_config.cve_enrichment?
        PackageMetadata::Ingestion::CveEnrichment::IngestionService.execute(data)
      elsif sync_config.advisories?
        PackageMetadata::Ingestion::Advisory::IngestionService.execute(data)
      else
        PackageMetadata::Ingestion::CompressedPackage::IngestionService.execute(data)
      end
    end

    def checkpoint
      @checkpoint ||= PackageMetadata::Checkpoint
        .with_path_components(sync_config.data_type, sync_config.version_format, sync_config.purl_type)
    end

    def resume_point
      return checkpoint unless sync_config.cve_enrichment?

      checkpoint if checkpoint.full_sync_target_sequence.present?
    end

    def advance_checkpoint(file)
      attributes = { sequence: file.sequence, chunk: file.chunk }
      attributes[:full_sync_target_sequence] = file.sequence if sync_config.cve_enrichment?

      checkpoint.update(attributes)
    end

    def finish_full_sync
      return unless sync_config.cve_enrichment? && checkpoint.full_sync_target_sequence.present?

      checkpoint.update(full_sync_target_sequence: nil)
    end

    def connector
      @connector ||= case sync_config.storage_type
                     when :gcp
                       Gitlab::PackageMetadata::Connector::Gcp.new(sync_config)
                     when :offline
                       offline_connector
                     else
                       raise UnknownAdapterError, "unable to find '#{sync_config.storage_type}' connector"
                     end
    end

    def offline_connector
      Gitlab::PackageMetadata::Connector::Offline.new(sync_config)
    end

    def throttle
      return if ENV['PM_SYNC_IN_DEV'] == 'true'

      sleep(THROTTLE_RATE)
    end
  end
end

# Added for JiHu
# Used in https://jihulab.com/gitlab-cn/gitlab/-/blob/main-jh/jh/app/services/jh/package_metadata/sync_service.rb
PackageMetadata::SyncService.prepend_mod
