# frozen_string_literal: true

module Geo
  class IssuableMetricImageUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :issuable_metric_image_upload_id

    belongs_to :issuable_metric_image_upload, inverse_of: :issuable_metric_image_upload_state, class_name: 'Geo::IssuableMetricImageUpload'

    validates :verification_state, :issuable_metric_image_upload, presence: true
  end
end
