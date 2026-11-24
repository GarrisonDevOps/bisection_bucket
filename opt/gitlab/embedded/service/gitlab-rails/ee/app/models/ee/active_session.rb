# frozen_string_literal: true

module EE
  module ActiveSession
    module ClassMethods
      def set_marketing_user_cookies(auth, user)
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        expiration_time = 2.weeks.from_now
        domain = ::Gitlab.config.gitlab.host

        auth.cookies[:gitlab_user] =
          {
            value: true,
            domain: domain,
            expires: expiration_time
          }

        tiers = ::GitlabSubscriptions::CurrentActivePlansForUserFinder.new(user).execute.map(&:name)

        auth.cookies[:gitlab_tier] = {
          value: tiers.presence || false,
          domain: domain,
          expires: expiration_time
        }
      end

      def unset_marketing_user_cookies(auth)
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        domain = ::Gitlab.config.gitlab.host

        auth.cookies.delete(:gitlab_user, domain: domain)
        auth.cookies.delete(:gitlab_tier, domain: domain)
      end
    end

    def self.prepended(base)
      base.singleton_class.prepend(ClassMethods)
    end
  end
end
