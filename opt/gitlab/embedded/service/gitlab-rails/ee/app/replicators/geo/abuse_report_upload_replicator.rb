# frozen_string_literal: true

module Geo
  class AbuseReportUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::AbuseReportUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Abuse Report Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Abuse Report Uploads')
    end
  end
end
