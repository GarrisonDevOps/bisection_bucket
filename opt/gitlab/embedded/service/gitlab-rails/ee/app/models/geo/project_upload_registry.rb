# frozen_string_literal: true

module Geo
  class ProjectUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :project_upload, class_name: 'Geo::ProjectUpload'

    def self.model_class
      ::Geo::ProjectUpload
    end

    def self.model_foreign_key
      :project_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
