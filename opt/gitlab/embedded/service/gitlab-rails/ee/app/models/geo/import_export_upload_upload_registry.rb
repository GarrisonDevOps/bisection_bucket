# frozen_string_literal: true

module Geo
  class ImportExportUploadUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :import_export_upload_upload, class_name: 'Geo::ImportExportUploadUpload'

    def self.model_class
      ::Geo::ImportExportUploadUpload
    end

    def self.model_foreign_key
      :import_export_upload_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
