# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      # No `override` annotation on the methods below: this module is
      # prepended into `Gitlab::Auth`'s singleton class (`class << self`),
      # and `Gitlab::Utils::Override` can't verify overrides on a singleton.

      # Public to match CE's visibility (lib/gitlab/auth.rb); a prepended
      # module's own visibility applies regardless of where CE's `private`
      # keyword falls.
      def git_client_checks(login, password, project, request)
        stateless_access_token_check(password) || super
      end

      private

      def unavailable_ai_features_scopes
        scopes = super
        scopes += ::Gitlab::Auth::AI_FEATURES_SCOPES unless ::Gitlab::CurrentSettings.duo_features_enabled
        scopes
      end

      def stateless_access_token_check(password)
        return unless password.present?

        # `from_jwt` returns nil on expiry too, and nil here falls through to
        # `super`, which tries the JWT against the other authentication
        # methods, such as database or LDAP.
        return unless ::Authn::Tokens::StatelessAccessToken.prefix?(password)

        token = ::Authn::Tokens::StatelessAccessToken.from_jwt(password)
        return ::Gitlab::Auth::Result::EMPTY unless token

        return ::Gitlab::Auth::Result::EMPTY unless ::Gitlab::Auth::StatelessAccessTokenGate.enabled?(token)
        return ::Gitlab::Auth::Result::EMPTY unless valid_oauth_token?(token)

        identity = ::Gitlab::Auth::Identity.link_from_oauth_token(token)
        return ::Gitlab::Auth::Result::EMPTY if identity && !identity.valid?

        user = token.user

        unless user.can_log_in_with_non_expired_password? || valid_composite_identity?(user)
          return ::Gitlab::Auth::Result::EMPTY
        end

        ::Gitlab::Auth::Result.new(user, nil, :stateless_access_token, abilities_for_scopes(token.scopes))
      end
    end
  end
end
