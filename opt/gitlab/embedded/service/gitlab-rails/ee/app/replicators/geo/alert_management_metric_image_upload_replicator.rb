# frozen_string_literal: true

module Geo
  class AlertManagementMetricImageUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior

    def self.model
      ::Geo::AlertManagementMetricImageUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Alert Management Metric Image Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Alert Management Metric Image Uploads')
    end
  end
end
