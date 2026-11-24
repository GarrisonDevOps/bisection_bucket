# frozen_string_literal: true

module Geo
  class OrganizationDetailUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :organization_detail_upload_id

    belongs_to :organization_detail_upload, inverse_of: :organization_detail_upload_state, class_name: 'Geo::OrganizationDetailUpload'

    validates :verification_state, :organization_detail_upload, presence: true
  end
end
