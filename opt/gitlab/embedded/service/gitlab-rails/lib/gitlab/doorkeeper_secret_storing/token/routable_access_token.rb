# frozen_string_literal: true

module Gitlab
  module DoorkeeperSecretStoring
    module Token
      class RoutableAccessToken
        ROUTING_PAYLOAD = {
          o: ->(attributes) { attributes[:organization_id] },
          u: ->(attributes) { attributes[:resource_owner_id] }
        }.freeze

        ROUTABLE_TOKEN = ::Authn::TokenField::Generator::RoutableToken

        TOKEN_VERSION = ROUTABLE_TOKEN::TOKEN_VERSION.to_s(36).rjust(ROUTABLE_TOKEN::TOKEN_VERSION_LENGTH, '0')

        # The token has no prefix, so the base64 payload is everything before the version
        # and is exactly as long as it says. Prefixed tokens such as routable PATs don't match, but a
        # PAT with a blank prefix does, which only costs a wasted sticking lookup.
        TOKEN_FORMAT = /\A(?<payload>[0-9A-Za-z_-]+)\.#{TOKEN_VERSION}\.
          (?<payload_length>[0-9a-z]{#{ROUTABLE_TOKEN::BASE64_PAYLOAD_LENGTH_HOLDER_BYTES}})
          [0-9a-z]{#{ROUTABLE_TOKEN::CRC_BYTES}}\z/x

        # Maintains compatibility with ::Doorkeeper::OAuth::Helpers::UniqueToken.
        # Doorkeeper passes the access token's attributes, including `organization_id`.
        def self.generate(options = {})
          return ::Doorkeeper::OAuth::Helpers::UniqueToken.generate(options) unless enabled?(options)

          ROUTABLE_TOKEN
            .new(options, routing_payload: ROUTING_PAYLOAD)
            .generate_token
        end

        def self.token?(plaintext)
          match = TOKEN_FORMAT.match(plaintext.to_s)

          match.present? && match[:payload].length == match[:payload_length].to_i(36)
        end

        def self.enabled?(options)
          actor = ::User.actor_from_id(options[:resource_owner_id]) if options[:resource_owner_id]

          Feature.enabled?(:routable_oauth_access_token, actor, type: :gitlab_com_derisk)
        end
        private_class_method :enabled?
      end
    end
  end
end
