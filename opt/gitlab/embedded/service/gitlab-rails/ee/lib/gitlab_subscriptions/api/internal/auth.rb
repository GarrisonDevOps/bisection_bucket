# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class Auth
        include Gitlab::Utils::StrongMemoize

        INTERNAL_API_REQUEST_HEADER = 'X-Customers-Dot-Internal-Token'
        AUDIENCE = 'gitlab-subscriptions'
        SUBJECT = 'customers-dot-internal-api'

        CACHE_KEYS = {
          openid_configuration: 'customers-dot-internal-api-oidc',
          jwks: 'customers-dot-internal-api-jwks'
        }.freeze

        def self.verify_api_request(headers)
          token = headers[INTERNAL_API_REQUEST_HEADER]

          new(token: token).decode if token.present?
        end

        def initialize(token:)
          @token = token
        end

        def decode
          return unless openid_configuration.present?
          return unless jwks.present?

          JWT.decode(token, nil, true, options)
        rescue JWT::DecodeError, JWT::ExpiredSignature
          nil
        end

        private

        attr_reader :token

        def options
          {
            algorithms: openid_configuration['id_token_signing_alg_values_supported'],
            jwks: jwks,
            iss: openid_configuration['issuer'],
            verify_iss: true,
            sub: SUBJECT,
            verify_sub: true,
            aud: AUDIENCE,
            verify_aud: true
          }
        end

        def jwks
          Rails.cache.fetch(CACHE_KEYS[:jwks], expires_in: 15.minutes, skip_nil: true) { fetch_jwks }
        end
        strong_memoize_attr :jwks

        def openid_configuration
          Rails.cache.fetch(CACHE_KEYS[:openid_configuration], expires_in: 1.day, skip_nil: true) do
            fetch_open_id_configuration
          end
        end
        strong_memoize_attr :openid_configuration

        def fetch_jwks
          response = Gitlab::HTTP.get(openid_configuration['jwks_uri'])

          return unless response.ok?

          response.parsed_response
        end

        def fetch_open_id_configuration
          response = Gitlab::HTTP.get(Gitlab::Routing.url_helpers.subscription_portal_openid_configuration_url)

          return unless response.ok?

          response.parsed_response
        end
      end
    end
  end
end
