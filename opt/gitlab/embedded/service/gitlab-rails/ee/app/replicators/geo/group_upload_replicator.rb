# frozen_string_literal: true

module Geo
  class GroupUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::GroupUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Group Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Group Uploads')
    end
  end
end
