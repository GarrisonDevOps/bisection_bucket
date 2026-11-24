# frozen_string_literal: true

module Geo
  class BulkImportExportUploadUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :bulk_import_export_upload_upload, class_name: 'Geo::BulkImportExportUploadUpload'

    def self.model_class
      ::Geo::BulkImportExportUploadUpload
    end

    def self.model_foreign_key
      :bulk_import_export_upload_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
