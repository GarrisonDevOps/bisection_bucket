# frozen_string_literal: true

module Emails
  module CiRunnerUsageByProject
    def runner_usage_by_project_csv_email(user:, scope:, from_date:, to_date:, csv_data:, export_status:)
      @count = export_status.fetch(:projects_expected)
      @scope = scope
      @written_count = export_status.fetch(:projects_written)
      @truncated = export_status.fetch(:truncated)
      @size_limit = ActiveSupport::NumberHelper.number_to_human_size(ExportCsv::BaseService::TARGET_FILESIZE)

      filename = "ci_runner_usage_report_#{from_date.iso8601}_#{to_date.iso8601}.csv"
      attachments[filename] = { content: csv_data, mime_type: 'text/csv' }
      email_with_layout(
        to: user.notification_email_or_default,
        subject: subject("Exported CI Runner usage (#{from_date.strftime('%F')} - #{to_date.strftime('%F')})"))
    end
  end
end
