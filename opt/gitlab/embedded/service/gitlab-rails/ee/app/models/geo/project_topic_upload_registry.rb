# frozen_string_literal: true

module Geo
  class ProjectTopicUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :project_topic_upload, class_name: 'Geo::ProjectTopicUpload'

    def self.model_class
      ::Geo::ProjectTopicUpload
    end

    def self.model_foreign_key
      :project_topic_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
