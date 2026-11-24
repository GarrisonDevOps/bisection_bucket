# frozen_string_literal: true

module ComplianceManagement
  class FrameworkExportMailerWorker
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

      unless csv_export&.success?
        raise ExportFailedError, 'An error occurred generating the compliance frameworks export'
      end

      Notify.compliance_frameworks_csv_email(
        user: @user,
        group: @group,
        attachment: csv_export.payload[:csv],
        truncated: csv_export.payload[:truncated],
        filename: filename
      ).deliver_now
    rescue ActiveRecord::RecordNotFound => e
      Gitlab::ErrorTracking.log_exception(e)
    end

    private

    def csv_export
      @csv_export ||= ComplianceManagement::Frameworks::ExportService.new(
        user: @user,
        group: @group
      ).execute
    end

    def filename
      "#{Date.current.iso8601}-compliance_frameworks_export-#{@group.id}.csv"
    end
  end
end
