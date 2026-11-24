# frozen_string_literal: true

module Namespaces
  module Storage
    class RepositoryLimitMailer < ApplicationMailer
      include EmailsHelper

      helper EmailsHelper

      layout 'mailer'

      def notify_out_of_storage(project_name:, recipients:)
        notify(
          safe_format(_('Action required: %{project_name} is read-only'), { project_name: project_name }),
          project_name,
          recipients
        )
      end

      def notify_limit_warning(project_name:, recipients:)
        notify(
          safe_format(
            _('Action required: Unusually high storage usage on %{project_name}'), { project_name: project_name }
          ),
          project_name,
          recipients
        )
      end

      def notify(subject, project_name, recipients)
        @support_url = Gitlab::Saas.customer_support_url
        @manage_storage_url = help_page_url('user/storage_usage_quotas.md', anchor: 'manage-storage-usage')
        @project_name = project_name

        mail_with_locale(
          bcc: recipients,
          subject: subject
        )
      end
    end
  end
end
