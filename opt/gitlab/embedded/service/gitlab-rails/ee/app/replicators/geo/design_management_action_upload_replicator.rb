# frozen_string_literal: true

module Geo
  class DesignManagementActionUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::DesignManagementActionUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Design Management Action Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Design Management Action Uploads')
    end
  end
end
