# frozen_string_literal: true

module Geo
  class DesignManagementActionUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :design_management_action_upload_id

    belongs_to :design_management_action_upload,
      inverse_of: :design_management_action_upload_state,
      class_name: 'Geo::DesignManagementActionUpload'

    validates :verification_state, :design_management_action_upload, presence: true
  end
end
