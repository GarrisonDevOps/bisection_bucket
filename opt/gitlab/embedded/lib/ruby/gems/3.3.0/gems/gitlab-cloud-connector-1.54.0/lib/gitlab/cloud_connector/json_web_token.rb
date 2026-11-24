# frozen_string_literal: true

require 'jwt'

module Gitlab
  module CloudConnector
    class JsonWebToken
      SIGNING_ALGORITHM = 'RS256'
      NOT_BEFORE_TIME_SEC = 5.seconds.to_i

      attr_reader :issued_at, :expires_at

      def initialize(issuer:, audience:, subject:, realm:, scopes:, ttl:, extra_claims: {})
        @id = SecureRandom.uuid
        @audience = audience
        @subject = subject
        @issuer = issuer
        @issued_at = Time.current.to_i
        @not_before = @issued_at - NOT_BEFORE_TIME_SEC
        @expires_at = (@issued_at + ttl).to_i
        @realm = realm
        @scopes = scopes
        @extra_claims = extra_claims
      end

      # jwk:
      #   The key (pair) as an instance of JWT::JWK.
      #
      # Returns a signed and Base64-encoded JSON Web Token string, to be
      # written to the HTTP Authorization header field.
      def encode(jwk)
        header_fields = { typ: 'JWT', kid: jwk.kid }

        JWT.encode(payload, jwk.signing_key, SIGNING_ALGORITHM, header_fields)
      end

      def payload
        {
          jti: @id,
          aud: @audience,
          sub: @subject,
          iss: @issuer,
          iat: @issued_at,
          nbf: @not_before,
          exp: @expires_at
        }.merge(cloud_connector_claims)
      end

      private

      def cloud_connector_claims
        {
          gitlab_realm: @realm,
          scopes: @scopes
        }.merge(@extra_claims)
      end
    end
  end
end
