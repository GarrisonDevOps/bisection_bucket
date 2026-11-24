# frozen_string_literal: true

module Authn
  module TokenExchange
    # A CI/CD ID token presented at the token exchange (ADR-020 R1). Everything is read
    # from the token, never the job record, so the IAM STS can perform the same exchange.
    class CiIdToken
      REQUIRED_CLAIMS = %w[jti exp user_id job_project_id sha pipeline_id job_id].freeze

      attr_reader :jti, :user_id, :expires_at, :job_claims

      class << self
        # The exchange URL, as every CI/CD ID token names its verifier. A service name
        # would not do: the registry trusts the same keys and `iss`, so it would accept
        # the ID token without any exchange.
        def audience
          # Interpolated, not joined, so it matches `$CI_SERVER_URL` byte for byte.
          "#{::Gitlab.config.gitlab.url}/api/#{::API::API.version}/token_exchange"
        end

        # Routing only: the unverified `aud` values when any is the exchange, else
        # none. A token with several still matches, so .from_jwt rejects it instead
        # of other handlers seeing it.
        def candidate_audiences(token_string)
          audiences = unverified_audiences(token_string)

          audiences.include?(audience) ? audiences : []
        end

        # Memoized per request: Rack::Attack and the API verify the same token, and
        # each rejection logs an error line.
        def from_jwt(token_string, audiences = candidate_audiences(token_string))
          return unless audiences == [audience]

          ::Gitlab::SafeRequestStore.fetch([:ci_id_token, token_string]) { verify(token_string) }
        end

        private

        def verify(token_string)
          result = ::Authn::IamService::JwtValidationService.new(
            token: token_string,
            jwks: -> { verification_keys },
            issuer: ::Gitlab.config.ci_id_tokens.issuer_url,
            audience: audience,
            required_claims: REQUIRED_CLAIMS,
            verify_not_before: true
          ).execute
          return unless result.success?

          build_from_payload(result.payload[:jwt_payload])
        end

        # Memoized per request: every bearer on an API path is decoded here, by the
        # finder and resolve_access_token, in both Rack::Attack and the API.
        def unverified_audiences(token_string)
          return [] unless token_string.is_a?(String)
          return [] if token_string.bytesize > ::Authn::IamService::JwtValidationService::MAX_TOKEN_SIZE_BYTES

          ::Gitlab::SafeRequestStore.fetch([:ci_id_token_audiences, token_string]) { decode_audiences(token_string) }
        end

        def decode_audiences(token_string)
          payload, _header = JWT.decode(token_string, nil, false)
          # The unverified decode accepts any JSON value, not only an object.
          return [] unless payload.is_a?(Hash)

          Array(payload['aud'])
        # A header that is not a JSON object raises outside JWT::DecodeError, and
        # ruby-jwt re-raises an ArgumentError from Base64 it does not recognize.
        rescue JWT::DecodeError, TypeError, NoMethodError, ArgumentError
          []
        end

        # Memoized per request: Rack::Attack and the API can verify the same token several times.
        def verification_keys
          ::Gitlab::SafeRequestStore.fetch(:ci_id_token_verification_keys) do
            key_data = ::Gitlab::CurrentSettings.ci_jwt_signing_key
            next { keys: [] } unless key_data

            # Same kid as Gitlab::Ci::JwtBase#kid, which signs the ID token.
            public_key = OpenSSL::PKey::RSA.new(key_data).public_key
            { keys: [JWT::JWK.new(public_key, kid: public_key.to_jwk[:kid]).export] }
          rescue OpenSSL::PKey::PKeyError => e
            ::Gitlab::ErrorTracking.track_exception(e)
            { keys: [] }
          end
        end

        def build_from_payload(payload)
          jti = payload['jti']
          # Logged as a string field, so any other JSON value would split the field's type.
          raise ArgumentError, 'jti is not a string' unless jti.is_a?(String) && jti.present?

          new(
            jti: jti,
            user_id: Integer(payload['user_id'], 10),
            expires_at: Time.zone.at(payload['exp']),
            job_claims: {
              project_id: Integer(payload['job_project_id'], 10),
              git_commit_sha: payload['sha'].presence || raise(ArgumentError, 'sha is blank'),
              pipeline_id: Integer(payload['pipeline_id'], 10),
              job_id: Integer(payload['job_id'], 10)
            }
          )
        rescue ArgumentError, TypeError
          nil
        end
      end

      def initialize(jti:, user_id:, expires_at:, job_claims:)
        @jti = jti
        @user_id = user_id
        @expires_at = expires_at
        @job_claims = job_claims
      end
    end
  end
end
