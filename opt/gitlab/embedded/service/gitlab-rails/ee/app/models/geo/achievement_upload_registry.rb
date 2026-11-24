# frozen_string_literal: true

module Geo
  class AchievementUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :achievement_upload, class_name: 'Geo::AchievementUpload'

    def self.model_class
      ::Geo::AchievementUpload
    end

    def self.model_foreign_key
      :achievement_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
