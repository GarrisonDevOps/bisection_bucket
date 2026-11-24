# frozen_string_literal: true

module Geo
  class ImportExportUploadUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :import_export_upload_upload_id

    belongs_to :import_export_upload_upload, inverse_of: :import_export_upload_upload_state,
      class_name: 'Geo::ImportExportUploadUpload'

    validates :verification_state, :import_export_upload_upload, presence: true
  end
end
