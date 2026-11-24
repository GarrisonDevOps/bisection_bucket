# frozen_string_literal: true

module Geo
  class BulkImportExportUploadUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :bulk_import_export_upload_upload_id

    belongs_to :bulk_import_export_upload_upload, inverse_of: :bulk_import_export_upload_upload_state,
      class_name: 'Geo::BulkImportExportUploadUpload'

    validates :verification_state, :bulk_import_export_upload_upload, presence: true
  end
end
