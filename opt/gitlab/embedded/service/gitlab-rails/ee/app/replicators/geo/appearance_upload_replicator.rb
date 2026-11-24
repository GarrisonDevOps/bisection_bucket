# frozen_string_literal: true

module Geo
  class AppearanceUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior

    def self.model
      ::Geo::AppearanceUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Appearance Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Appearance Uploads')
    end
  end
end
