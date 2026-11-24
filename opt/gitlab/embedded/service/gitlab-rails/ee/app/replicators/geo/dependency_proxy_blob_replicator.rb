# frozen_string_literal: true

module Geo
  class DependencyProxyBlobReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::DependencyProxy::Blob
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Dependency Proxy Blob')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Dependency Proxy Blobs')
    end

    def carrierwave_uploader
      model_record.file
    end
  end
end
