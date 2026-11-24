# frozen_string_literal: true

module Geo
  class AppearanceUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :appearance_upload_id

    belongs_to :appearance_upload, inverse_of: :appearance_upload_state, class_name: 'Geo::AppearanceUpload'

    validates :verification_state, :appearance_upload, presence: true
  end
end
