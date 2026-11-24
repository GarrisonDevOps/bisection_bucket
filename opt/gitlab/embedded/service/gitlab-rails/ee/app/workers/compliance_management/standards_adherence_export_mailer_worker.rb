# frozen_string_literal: true

module ComplianceManagement
  class StandardsAdherenceExportMailerWorker
    ExportFailedError = Class.new StandardError

    include ApplicationWorker

    version 1
    feature_category :compliance_management
    deduplicate :until_executed, including_scheduled: true
    data_consistency :delayed
    urgency :low
    idempotent!

    def perform(user_id, group_id)
      @user = User.find user_id
      @group = Namespace.find group_id

      raise ExportFailedError, 'An error occurred generating the standards adherence export' unless csv_export&.success?

      Notify.compliance_standards_adherence_csv_email(
        user: @user,
        group: @group,
        attachment: csv_export.payload,
        filename: filename
      ).deliver_now
    rescue ActiveRecord::RecordNotFound => e
      Gitlab::ErrorTracking.log_exception(e)
    end

    private

    def csv_export
      @csv_export ||= ComplianceManagement::Standards::ExportService.new(
        user: @user,
        group: @group
      ).execute
    end

    def filename
      "#{Date.current.iso8601}-compliance_standards_adherence_export-#{@group.id}.csv"
    end
  end
end
