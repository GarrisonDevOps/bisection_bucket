# frozen_string_literal: true

module Geo
  class AchievementUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :achievement_upload_id

    belongs_to :achievement_upload, inverse_of: :achievement_upload_state, class_name: 'Geo::AchievementUpload'

    validates :verification_state, :achievement_upload, presence: true
  end
end
