# frozen_string_literal: true

module Users
  class CompromisedPasswordDetectionMailer < ApplicationMailer
    helper EmailsHelper
    include SafeFormatHelper

    layout 'mailer'

    def compromised_password_detection_email(user)
      @user = user

      @url_to_change_password_docs = help_page_url('user/profile/user_passwords.md', anchor: 'change-your-password')

      @url_to_mfa_docs = help_page_url('user/profile/account/two_factor_authentication.md',
        anchor: 'enable-two-factor-authentication')

      mail_with_locale(
        to: user.notification_email_or_default,
        subject: subject(s_("CompromisedPasswordDetection|Security Alert: Change Your GitLab.com Password"))
      )
    end
  end
end
