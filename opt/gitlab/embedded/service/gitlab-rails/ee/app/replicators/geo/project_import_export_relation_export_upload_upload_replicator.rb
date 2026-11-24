# frozen_string_literal: true

module Geo
  class ProjectImportExportRelationExportUploadUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::ProjectImportExportRelationExportUploadUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Relation Export File Upload')
    end

    def self.replicable_title_plural
      s_('Geo|Relation Export File Uploads')
    end
  end
end
