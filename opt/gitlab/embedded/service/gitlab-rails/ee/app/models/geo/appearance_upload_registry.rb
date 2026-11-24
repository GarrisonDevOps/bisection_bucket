# frozen_string_literal: true

module Geo
  class AppearanceUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :appearance_upload, class_name: 'Geo::AppearanceUpload'

    def self.model_class
      ::Geo::AppearanceUpload
    end

    def self.model_foreign_key
      :appearance_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
