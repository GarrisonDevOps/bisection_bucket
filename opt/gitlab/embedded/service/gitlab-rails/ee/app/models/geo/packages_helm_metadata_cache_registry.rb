# frozen_string_literal: true

module Geo
  class PackagesHelmMetadataCacheRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :packages_helm_metadata_cache, class_name: 'Packages::Helm::MetadataCache'

    def self.model_class
      ::Packages::Helm::MetadataCache
    end

    def self.model_foreign_key
      :packages_helm_metadata_cache_id
    end
  end
end
