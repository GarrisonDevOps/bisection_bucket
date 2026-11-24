# frozen_string_literal: true

module Geo
  class UserUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::UserUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|User Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|User Uploads')
    end
  end
end
