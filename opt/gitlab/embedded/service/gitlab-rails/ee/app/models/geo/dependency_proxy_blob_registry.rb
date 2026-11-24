# frozen_string_literal: true

module Geo
  class DependencyProxyBlobRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :dependency_proxy_blob, class_name: 'DependencyProxy::Blob'

    def self.model_class
      ::DependencyProxy::Blob
    end

    def self.model_foreign_key
      :dependency_proxy_blob_id
    end
  end
end
