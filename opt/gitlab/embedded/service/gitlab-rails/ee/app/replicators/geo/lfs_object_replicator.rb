# frozen_string_literal: true

module Geo
  class LfsObjectReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    extend ::Gitlab::Utils::Override

    def carrierwave_uploader
      model_record.file
    end

    # LfsObjectUploader stores the oid as dir/dir/rest, so removing the slashes gives the oid back.
    override :blob_location_in_use?
    def blob_location_in_use?(blob_path, _uploader_class)
      model.for_oids(blob_path.delete('/')).exists?
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|LFS Object')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|LFS Objects')
    end

    def self.model
      ::LfsObject
    end
  end
end
