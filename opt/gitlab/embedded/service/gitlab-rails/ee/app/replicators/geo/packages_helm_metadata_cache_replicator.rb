# frozen_string_literal: true

module Geo
  class PackagesHelmMetadataCacheReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    event ::Geo::ReplicatorEvents::EVENT_UPDATED

    def self.model
      ::Packages::Helm::MetadataCache
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Helm Metadata Cache')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Helm Metadata Caches')
    end

    def carrierwave_uploader
      model_record.file
    end

    # Called by Gitlab::Geo::Replicator#consume
    def consume_event_updated(...)
      consume_event_created(...)
    end

    def immutable?
      false
    end

    # The path is the object storage key plus the file name, and the key comes from the project and channel.
    override :blob_location_in_use?
    def blob_location_in_use?(blob_path, _uploader_class)
      model.with_object_storage_key(File.dirname(blob_path)).exists?
    end
  end
end
