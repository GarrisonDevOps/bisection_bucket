# frozen_string_literal: true

module Geo
  class UserPermissionExportUploadUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :user_permission_export_upload_upload, class_name: 'Geo::UserPermissionExportUploadUpload'

    def self.model_class
      ::Geo::UserPermissionExportUploadUpload
    end

    def self.model_foreign_key
      :user_permission_export_upload_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
