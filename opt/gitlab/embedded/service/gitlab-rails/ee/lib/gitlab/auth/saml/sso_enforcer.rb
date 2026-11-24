# frozen_string_literal: true

module Gitlab
  module Auth
    module Saml
      class SsoEnforcer
        DEFAULT_SESSION_TIMEOUT = 1.day

        attr_reader :user, :session_timeout

        def initialize(user: nil, session_timeout: DEFAULT_SESSION_TIMEOUT)
          @user = user
          @session_timeout = session_timeout
        end

        def active_session?
          saml_providers.any? do |provider|
            SsoState.new(provider_id: provider).active_since?(session_timeout.ago)
          end
        end

        def access_restricted?
          saml_enforced? && !active_session?
        end

        private

        def saml_providers
          ::AuthHelper.saml_providers
        end

        def saml_enforced?
          return false unless user
          return false if user.allow_password_authentication_for_web? || user.password_based_omniauth_user?

          user.identities.with_provider(saml_providers).exists?
        end
      end
    end
  end
end
