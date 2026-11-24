# frozen_string_literal: true

module Geo
  class AlertManagementMetricImageUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :alert_management_metric_image_upload, class_name: 'Geo::AlertManagementMetricImageUpload'

    def self.model_class
      ::Geo::AlertManagementMetricImageUpload
    end

    def self.model_foreign_key
      :alert_management_metric_image_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
