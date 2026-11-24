# frozen_string_literal: true

module Geo
  class ProjectTopicUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :project_topic_upload_id

    belongs_to :project_topic_upload, inverse_of: :project_topic_upload_state, class_name: 'Geo::ProjectTopicUpload'

    validates :verification_state, :project_topic_upload, presence: true
  end
end
