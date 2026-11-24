# frozen_string_literal: true

class Admin::AuditLogReportsController < Admin::ApplicationController
  include AuditEvents::EnforcesValidDateParams
  include AuditEvents::AuditEventsParams
  include AuditEvents::DateRange

  before_action :validate_audit_event_reports_available!

  feature_category :audit_events

  def index
    csv_data = AuditEvents::ExportCsvService.new(audit_events_params.to_h).csv_data

    respond_to do |format|
      format.csv do
        stream_csv_headers(csv_filename)

        self.response_body = csv_data
      end
    end
  end

  private

  def validate_audit_event_reports_available!
    render_404 unless License.feature_available?(:admin_audit_log)
  end

  def csv_filename
    "audit-events-#{Time.current.to_i}.csv"
  end
end
