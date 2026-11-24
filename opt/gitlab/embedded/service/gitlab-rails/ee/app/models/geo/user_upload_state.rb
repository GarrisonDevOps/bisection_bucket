# frozen_string_literal: true

module Geo
  class UserUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :user_upload_id

    belongs_to :user_upload, inverse_of: :user_upload_state, class_name: 'Geo::UserUpload'

    validates :verification_state, :user_upload, presence: true
  end
end
