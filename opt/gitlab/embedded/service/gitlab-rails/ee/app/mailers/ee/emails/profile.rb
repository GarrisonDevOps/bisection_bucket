# frozen_string_literal: true

module EE
  module Emails
    module Profile
      def policy_revoked_personal_access_tokens_email(user, revoked_token_names)
        return unless user && revoked_token_names

        @user = user
        @revoked_token_names = revoked_token_names
        @target_url = user_settings_personal_access_tokens_url

        ::Gitlab::I18n.with_locale(@user.preferred_language) do
          mail(to: user.notification_email_or_default, subject: subject(_("One or more of you personal access tokens were revoked")))
        end
      end

      def pipl_compliance_notification(user, deadline)
        @deadline = deadline.strftime("%B %d, %Y")

        ::Gitlab::I18n.with_locale(user.preferred_language) do
          mail(to: user.notification_email_or_default, subject: subject(s_("PIPL|Important Change to Your GitLab.com Account")))
        end
      end
    end
  end
end
