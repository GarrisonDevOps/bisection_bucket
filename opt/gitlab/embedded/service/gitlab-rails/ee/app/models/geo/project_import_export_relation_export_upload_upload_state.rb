# frozen_string_literal: true

module Geo
  class ProjectImportExportRelationExportUploadUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :project_import_export_relation_export_upload_upload_id

    belongs_to :project_import_export_relation_export_upload_upload,
      inverse_of: :project_import_export_relation_export_upload_upload_state,
      class_name: 'Geo::ProjectImportExportRelationExportUploadUpload'

    validates :verification_state, :project_import_export_relation_export_upload_upload, presence: true
  end
end
