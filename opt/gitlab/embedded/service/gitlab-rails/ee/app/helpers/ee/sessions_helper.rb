# frozen_string_literal: true

module EE
  module SessionsHelper
    extend ::Gitlab::Utils::Override

    override :show_passkey_immediately?
    def show_passkey_immediately?
      # The passkey sign-in needs the user's cell resolved first, and this SaaS feature returns true only in the
      # cells architecture (GitLab.com), not in GitLab Self-Managed or GitLab Dedicated.
      return false if ::Gitlab::Saas.feature_available?(:redirect_sign_in_when_login_not_found)

      super
    end
  end
end
