# frozen_string_literal: true

module Geo
  class AchievementUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::AchievementUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Achievement Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Achievement Uploads')
    end
  end
end
