# frozen_string_literal: true

module Geo
  class GroupUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :group_upload, class_name: 'Geo::GroupUpload'

    def self.model_class
      ::Geo::GroupUpload
    end

    def self.model_foreign_key
      :group_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
