# frozen_string_literal: true

module Geo
  class DependencyListExportUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :dependency_list_export_upload, class_name: 'Geo::DependencyListExportUpload'

    def self.model_class
      ::Geo::DependencyListExportUpload
    end

    def self.model_foreign_key
      :dependency_list_export_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
