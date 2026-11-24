# frozen_string_literal: true

module EE
  module Gitlab
    module Tracking
      module BillingAuthEmitter
        extend ::Gitlab::Utils::Override

        TOKEN_CACHE_TTL_BUFFER = 60

        override :initialize
        def initialize(endpoint:, options: {})
          @cc_token_mutex = Mutex.new
          super
        end

        private

        # SM/Dedicated instances can't mint GCP IAM OIDC tokens, so they present
        # their Cloud Connector token (the same JWT sent to the Duo AI gateway).
        override :auth_token
        def auth_token
          return super if ::CloudConnector.gitlab_realm == ::CloudConnector::GITLAB_REALM_SAAS

          cloud_connector_token
        end

        # rubocop:disable Gitlab/ModuleWithInstanceVariables -- per-instance token cache owned here, initialized in #initialize
        def cloud_connector_token
          @cc_token_mutex.synchronize do
            @cached_cc_token = fetch_cloud_connector_token unless cached_cc_token_valid?
            @cached_cc_token
          end
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
          nil
        end

        def cached_cc_token_valid?
          @cached_cc_token.present? && @cc_expires_at.present? && Time.now.to_i < @cc_expires_at
        end

        def fetch_cloud_connector_token
          token = ::CloudConnector::Tokens.cloud_connector_token
          return unless token

          @cc_expires_at = token_expiry(token)
          token
        end
        # rubocop:enable Gitlab/ModuleWithInstanceVariables

        def token_expiry(token)
          # Decoded without signature verification: we only read `exp` to cache
          # the token; the collector is the party that verifies it.
          payload, _header = JWT.decode(token, nil, false)
          exp = payload['exp']
          raise "Cloud Connector token is missing 'exp' claim" unless exp

          exp.to_i - TOKEN_CACHE_TTL_BUFFER
        end
      end
    end
  end
end
