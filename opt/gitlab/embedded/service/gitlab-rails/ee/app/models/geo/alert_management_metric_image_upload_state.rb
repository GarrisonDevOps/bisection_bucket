# frozen_string_literal: true

module Geo
  class AlertManagementMetricImageUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :alert_management_metric_image_upload_id

    belongs_to :alert_management_metric_image_upload, inverse_of: :alert_management_metric_image_upload_state,
      class_name: 'Geo::AlertManagementMetricImageUpload'

    validates :verification_state, :alert_management_metric_image_upload, presence: true
  end
end
