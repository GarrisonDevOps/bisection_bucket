# frozen_string_literal: true

module Vulnerabilities
  class ExportMailer < ApplicationMailer
    helper ::EmailsHelper
    helper ::VulnerabilitiesHelper

    layout 'mailer'

    def completion_email(export)
      @export = export
      @expiration_days = Vulnerabilities::Export::EXPIRES_AFTER.in_days.to_i

      exportable = export.exportable

      group = case exportable
              when ::Project
                exportable.group
              when ::Group
                exportable
              end

      dashboard_type = export.report_data&.fetch('dashboard_type', nil)
      subject_label = subject_label_for(dashboard_type)

      mail_with_locale(
        to: export.author.notification_email_for(group),
        subject: subject(exportable_name(exportable), subject_label)
      )
    end

    private

    def exportable_name(exportable)
      case exportable
      when InstanceSecurityDashboard
        s_('Vulnerabilities|Your personal dashboard')
      else
        exportable.name
      end
    end

    def subject_label_for(dashboard_type)
      if dashboard_type.present?
        s_('Vulnerabilities|Security Dashboard export')
      else
        s_('Vulnerabilities|Vulnerability Report export')
      end
    end
  end
end
