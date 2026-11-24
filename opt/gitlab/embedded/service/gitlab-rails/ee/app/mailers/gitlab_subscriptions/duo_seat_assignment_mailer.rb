# frozen_string_literal: true

module GitlabSubscriptions
  class DuoSeatAssignmentMailer < ApplicationMailer
    helper SafeFormatHelper
    helper EmailsHelper

    def duo_pro_email(user)
      email = user.notification_email_or_default
      mail_with_locale(to: email, subject: s_('CodeSuggestions|Welcome to GitLab Duo Pro!'))
    end

    def duo_enterprise_email(user)
      email = user.notification_email_or_default
      mail_with_locale(to: email, subject: s_('DuoEnterprise|Welcome to GitLab Duo Enterprise!'))
    end
  end
end
