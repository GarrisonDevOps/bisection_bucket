# frozen_string_literal: true

module Geo
  class PackagesDebianProjectComponentFileReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::Packages::Debian::ProjectComponentFile
    end

    # The uploader reads component.distribution to build the path.
    def self.blob_location_preloads
      [{ component: :distribution }]
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Debian Project Component File')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Debian Project Component Files')
    end

    def carrierwave_uploader
      model_record.file
    end
  end
end
