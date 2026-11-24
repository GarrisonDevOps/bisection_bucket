# frozen_string_literal: true

module Geo
  class AbuseReportUploadState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    self.primary_key = :abuse_report_upload_id

    belongs_to :abuse_report_upload, inverse_of: :abuse_report_upload_state, class_name: 'Geo::AbuseReportUpload'

    validates :verification_state, :abuse_report_upload, presence: true
  end
end
