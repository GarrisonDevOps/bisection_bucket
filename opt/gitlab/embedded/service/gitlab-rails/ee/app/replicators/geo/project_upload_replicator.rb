# frozen_string_literal: true

module Geo
  class ProjectUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::ProjectUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Project Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Project Uploads')
    end
  end
end
