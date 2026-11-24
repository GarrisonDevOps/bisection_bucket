# frozen_string_literal: true

module Geo
  class ImportExportUploadUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::ImportExportUploadUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Import/Export Archive Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Import/Export Archive Uploads')
    end
  end
end
