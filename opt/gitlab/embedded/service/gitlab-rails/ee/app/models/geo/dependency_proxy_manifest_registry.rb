# frozen_string_literal: true

module Geo
  class DependencyProxyManifestRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :dependency_proxy_manifest, class_name: 'DependencyProxy::Manifest'

    def self.model_class
      ::DependencyProxy::Manifest
    end

    def self.model_foreign_key
      :dependency_proxy_manifest_id
    end
  end
end
