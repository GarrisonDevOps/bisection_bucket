# frozen_string_literal: true

module Geo
  class GroupUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :group_upload_id

    belongs_to :group_upload, inverse_of: :group_upload_state, class_name: 'Geo::GroupUpload'

    validates :verification_state, :group_upload, presence: true
  end
end
