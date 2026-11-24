# frozen_string_literal: true

module ComplianceManagement
  module Groups
    class ComplianceViolationsExportMailerWorker
      include ApplicationWorker

      ExportFailedError = Class.new(StandardError)
      DB_HEALTH_DEFER_DELAY = 3.minutes.freeze

      version 1
      feature_category :compliance_management
      deduplicate :until_executed, including_scheduled: true
      data_consistency :delayed
      defer_on_database_health_signal :gitlab_main, [:users, :namespaces], DB_HEALTH_DEFER_DELAY
      urgency :low
      idempotent!

      def perform(user_id, group_id)
        @user = User.find_by_id(user_id)
        @group = Group.find_by_id(group_id)

        return unless @user && @group

        export_result = csv_export
        unless export_result.success?
          error_message = export_result.message || 'An error occurred generating the violations export'
          raise ExportFailedError, error_message
        end

        Notify.compliance_violations_csv_email(
          user: @user,
          group: @group,
          attachment: export_result.payload,
          filename: filename
        ).deliver_now
      end

      private

      def csv_export
        ::ComplianceManagement::Groups::ComplianceViolations::ExportService.new(
          user: @user,
          group: @group
        ).execute
      end

      def filename
        "#{Date.current.iso8601}-group_compliance_violations_export-#{@group.id}.csv"
      end
    end
  end
end
