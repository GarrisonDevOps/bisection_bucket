# frozen_string_literal: true

module Geo
  class AbuseReportUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :abuse_report_upload, class_name: 'Geo::AbuseReportUpload'

    def self.model_class
      ::Geo::AbuseReportUpload
    end

    def self.model_foreign_key
      :abuse_report_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end
