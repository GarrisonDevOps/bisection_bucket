# frozen_string_literal: true

module Geo
  class BulkImportExportUploadUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::BulkImportExportUploadUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Bulk import/export archive upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Bulk import/export archive uploads')
    end
  end
end
