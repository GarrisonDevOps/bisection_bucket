# frozen_string_literal: true

module Geo
  class ProjectTopicUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior

    def self.model
      ::Geo::ProjectTopicUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Project Topic Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Project Topic Uploads')
    end
  end
end
