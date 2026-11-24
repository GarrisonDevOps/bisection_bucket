# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class RevokeTokenService
      def initialize(token:, current_user:)
        @token = token
        @current_user = current_user
      end

      def execute
        # An expired JWT fails from_jwt and takes the Doorkeeper path to an RFC 7009
        # success with no denylist entry. The verifier allows no expiry leeway, so
        # the only remaining acceptance window is clock skew between nodes.
        token = ::Authn::Tokens::StatelessAccessToken.from_jwt(@token)

        return revoke_jwt(token) if token

        revoke_doorkeeper_token
      end

      private

      def revoke_jwt(token)
        unless valid_token_ownership?(token)
          return ServiceResponse.error(message: "Invalid token ownership", reason: :invalid_token_ownership)
        end

        # Uses includes_scope? instead of acceptable? on purpose: revocation must
        # still work when the user is no longer active, which acceptable? rejects.
        unless token.includes_scope?("ai_workflows")
          return ServiceResponse.error(message: "Insufficient token scope", reason: :insufficient_token_scope)
        end

        ::Authn::Tokens::StatelessAccessToken::Denylist.deny!(token)

        ServiceResponse.success(payload: {}, message: "Token revoked")
      end

      def revoke_doorkeeper_token
        doorkeeper_token = OauthAccessToken.by_token(@token)

        # Invalid tokens do not cause an error response as per https://datatracker.ietf.org/doc/html/rfc7009
        return ServiceResponse.success(payload: {}, message: "Token revoked") unless doorkeeper_token.present?

        # Ensure token belongs to the authenticated user
        unless valid_token_ownership?(doorkeeper_token)
          return ServiceResponse.error(message: "Invalid token ownership", reason: :invalid_token_ownership)
        end

        # This service should only revoke ai_workflows scoped tokens
        unless doorkeeper_token.acceptable?("ai_workflows")
          return ServiceResponse.error(message: "Insufficient token scope", reason: :insufficient_token_scope)
        end

        revoked = doorkeeper_token.revoke

        return ServiceResponse.success(payload: {}, message: "Token revoked") if revoked

        ServiceResponse.error(message: "Could not revoke token", reason: :failed_to_revoke)
      end

      def valid_token_ownership?(token)
        return token.scope_user == @current_user if token.user&.composite_identity_enforced? && token.scope_user

        token.resource_owner == @current_user
      end
    end
  end
end
