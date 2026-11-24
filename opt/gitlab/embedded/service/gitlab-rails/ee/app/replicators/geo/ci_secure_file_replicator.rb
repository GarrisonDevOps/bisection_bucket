# frozen_string_literal: true

module Geo
  class CiSecureFileReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::Ci::SecureFile
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|CI Secure File')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|CI Secure Files')
    end

    def carrierwave_uploader
      model_record.file
    end
  end
end
