# frozen_string_literal: true

module Geo
  class ProjectImportExportRelationExportUploadUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :project_import_export_relation_export_upload_upload,
      class_name: 'Geo::ProjectImportExportRelationExportUploadUpload'

    def self.model_class
      ::Geo::ProjectImportExportRelationExportUploadUpload
    end

    def self.model_foreign_key
      :project_import_export_relation_export_upload_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
