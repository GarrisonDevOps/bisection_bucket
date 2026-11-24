# frozen_string_literal: true

module Geo
  class UserPermissionExportUploadUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :user_permission_export_upload_upload_id

    belongs_to :user_permission_export_upload_upload,
      inverse_of: :user_permission_export_upload_upload_state,
      class_name: 'Geo::UserPermissionExportUploadUpload'

    validates :verification_state, :user_permission_export_upload_upload, presence: true
  end
end
