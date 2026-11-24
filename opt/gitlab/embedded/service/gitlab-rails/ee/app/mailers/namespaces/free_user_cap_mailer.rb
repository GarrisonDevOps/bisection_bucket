# frozen_string_literal: true

module Namespaces
  class FreeUserCapMailer < ApplicationMailer
    helper ::Namespaces::FreeUserCapHelper
    helper EmailsHelper
    include SafeFormatHelper

    layout 'mailer'

    def over_limit_email(user, namespace)
      email = user.notification_email_or_default

      @start_trial_url = new_trial_url
      @upgrade_url = group_billings_url(namespace)
      @manage_users_url = group_usage_quotas_url(namespace, anchor: 'seats-quota-tab')
      @namespace_name = namespace.name
      @trial_duration = GitlabSubscriptions::TrialDurationService.new.execute

      mail_with_locale(
        to: email,
        subject: safe_format(
          s_('FreeUserCap|Action required: %{namespace_name} group has been placed into a read-only state'),
          namespace_name: @namespace_name)
      )
    end
  end
end
