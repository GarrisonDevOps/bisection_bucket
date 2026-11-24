# frozen_string_literal: true

module Geo
  class DependencyListExportPartUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :dependency_list_export_part_upload, class_name: 'Geo::DependencyListExportPartUpload'

    def self.model_class
      ::Geo::DependencyListExportPartUpload
    end

    def self.model_foreign_key
      :dependency_list_export_part_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
