# frozen_string_literal: true

module Geo
  class DependencyListExportUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :dependency_list_export_upload_id

    belongs_to :dependency_list_export_upload, inverse_of: :dependency_list_export_upload_state, class_name: 'Geo::DependencyListExportUpload'

    validates :verification_state, :dependency_list_export_upload, presence: true
  end
end
