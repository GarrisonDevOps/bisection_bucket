# frozen_string_literal: true

module Geo
  class OrganizationDetailUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :organization_detail_upload, class_name: 'Geo::OrganizationDetailUpload'

    def self.model_class
      ::Geo::OrganizationDetailUpload
    end

    def self.model_foreign_key
      :organization_detail_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
