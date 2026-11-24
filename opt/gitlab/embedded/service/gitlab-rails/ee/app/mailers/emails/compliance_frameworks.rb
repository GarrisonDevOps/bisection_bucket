# frozen_string_literal: true

module Emails
  module ComplianceFrameworks
    def compliance_frameworks_csv_email(user:, group:, attachment:, filename:, truncated: false)
      @group = group
      @truncated = truncated
      attachments[filename] = { content: attachment, mime_type: 'text/csv' }

      email_with_layout(
        to: user.notification_email_for(group),
        subject: subject(Date.current.iso8601 + s_("ComplianceFrameworks| Frameworks export"))
      )
    end
  end
end
