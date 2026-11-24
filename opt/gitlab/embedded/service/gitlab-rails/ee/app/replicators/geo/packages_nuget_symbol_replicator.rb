# frozen_string_literal: true

module Geo
  class PackagesNugetSymbolReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::Packages::Nuget::Symbol
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|NuGet Symbol')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|NuGet Symbols')
    end

    def carrierwave_uploader
      model_record.file
    end

    # The path is the object storage key plus the file name, and the key comes from the package and signature.
    override :blob_location_in_use?
    def blob_location_in_use?(blob_path, _uploader_class)
      model.with_object_storage_key(File.dirname(blob_path)).exists?
    end
  end
end
