# frozen_string_literal: true

module Authn
  module Tokens
    class ScimAccessToken
      def self.prefix?(plaintext)
        prefixes = [
          ::ScimOauthAccessToken::TOKEN_PREFIX,
          ::GroupScimAuthAccessToken::TOKEN_PREFIX,
          ::ScimOauthAccessToken.prefix_for_token,
          ::GroupScimAuthAccessToken.prefix_for_token
        ].uniq

        plaintext.start_with?(*prefixes)
      end

      attr_reader :revocable, :source

      def initialize(plaintext, source)
        @revocable = ::ScimOauthAccessToken.find_by_token(plaintext) ||
          ::GroupScimAuthAccessToken.find_by_token(plaintext)
        @source = source
      end

      def present_with
        if revocable.is_a?(::ScimOauthAccessToken)
          ::API::Entities::ScimOauthAccessToken
        elsif revocable.is_a?(::GroupScimAuthAccessToken)
          ::API::Entities::GroupScimAuthAccessToken
        end
      end

      def revoke!(current_user)
        raise ::Authn::AgnosticTokenIdentifier::NotFoundError, 'Not Found' if revocable.blank?

        ::Authn::ScimAccessTokens::ResetService.new(
          current_user: current_user,
          token: revocable,
          audit_source: source
        ).execute
      end
    end
  end
end
