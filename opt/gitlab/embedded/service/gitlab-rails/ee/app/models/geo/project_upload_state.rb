# frozen_string_literal: true

module Geo
  class ProjectUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :project_upload_id

    belongs_to :project_upload, inverse_of: :project_upload_state, class_name: 'Geo::ProjectUpload'

    validates :verification_state, :project_upload, presence: true
  end
end
