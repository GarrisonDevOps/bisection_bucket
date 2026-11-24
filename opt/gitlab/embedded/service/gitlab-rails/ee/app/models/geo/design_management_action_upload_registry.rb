# frozen_string_literal: true

module Geo
  class DesignManagementActionUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :design_management_action_upload, class_name: 'Geo::DesignManagementActionUpload'

    def self.model_class
      ::Geo::DesignManagementActionUpload
    end

    def self.model_foreign_key
      :design_management_action_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
