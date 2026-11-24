# frozen_string_literal: true

module Geo
  class DependencyListExportPartUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :dependency_list_export_part_upload_id

    belongs_to :dependency_list_export_part_upload, inverse_of: :dependency_list_export_part_upload_state,
      class_name: 'Geo::DependencyListExportPartUpload'

    validates :verification_state, :dependency_list_export_part_upload, presence: true
  end
end
