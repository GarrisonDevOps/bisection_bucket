# frozen_string_literal: true

module Geo
  class PersonalSnippetUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :personal_snippet_upload_id

    belongs_to :personal_snippet_upload, inverse_of: :personal_snippet_upload_state, class_name: 'Geo::PersonalSnippetUpload'

    validates :verification_state, :personal_snippet_upload, presence: true
  end
end
