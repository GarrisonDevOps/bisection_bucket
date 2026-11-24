# frozen_string_literal: true

module Geo
  class OrganizationDetailUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior

    def self.model
      ::Geo::OrganizationDetailUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Organization Detail Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Organization Detail Uploads')
    end
  end
end
