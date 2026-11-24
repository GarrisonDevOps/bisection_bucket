# frozen_string_literal: true

module Geo
  class UserUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :user_upload, class_name: 'Geo::UserUpload'

    def self.model_class
      ::Geo::UserUpload
    end

    def self.model_foreign_key
      :user_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
