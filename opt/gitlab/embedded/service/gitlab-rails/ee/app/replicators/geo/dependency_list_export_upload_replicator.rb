# frozen_string_literal: true

module Geo
  class DependencyListExportUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior

    def self.model
      ::Geo::DependencyListExportUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Dependency List Export Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Dependency List Export Uploads')
    end
  end
end
