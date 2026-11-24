# frozen_string_literal: true

module Geo
  class DependencyProxyManifestReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::DependencyProxy::Manifest
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Dependency Proxy Manifest')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Dependency Proxy Manifests')
    end

    def carrierwave_uploader
      model_record.file
    end
  end
end
