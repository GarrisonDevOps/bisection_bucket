# frozen_string_literal: true

module Geo
  class IssuableMetricImageUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :issuable_metric_image_upload, class_name: 'Geo::IssuableMetricImageUpload'

    def self.model_class
      ::Geo::IssuableMetricImageUpload
    end

    def self.model_foreign_key
      :issuable_metric_image_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
