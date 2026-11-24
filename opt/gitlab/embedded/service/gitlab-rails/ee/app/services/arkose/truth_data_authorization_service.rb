# frozen_string_literal: true

module Arkose
  class TruthDataAuthorizationService
    TRUTH_DATA_AUTHORIZATION_ENDPOINT = 'https://client-api.arkoselabs.com/truth_data_api/v1/authorize'
    AUTHORIZATION_TOKEN_CACHE_KEY = 'arkose_truth_data_client_access_token'

    class << self
      def execute
        cached_token = Rails.cache.fetch(AUTHORIZATION_TOKEN_CACHE_KEY)
        return success(cached_token) if cached_token

        fetch_auth_token
      end

      private

      def fetch_auth_token
        response = Gitlab::HTTP.perform_request(
          Net::HTTP::Post, TRUTH_DATA_AUTHORIZATION_ENDPOINT,
          body: authorize_body
        )

        return error(response) unless response.code == HTTP::Status::OK

        # Subtract 60 seconds to avoid race conditions. The token will be valid for 24 hours.
        # https://developer.arkoselabs.com/docs/truth-data-system#sending-truth-data-via-new-api
        Rails.cache.write(
          AUTHORIZATION_TOKEN_CACHE_KEY,
          response['access_token'],
          expires_in: response['expires_in'] - 60
        )

        success(response['access_token'])
      end

      def authorize_body
        {
          client_id: AntiAbuse::IdentityVerification::Settings.arkose_client_id,
          client_secret: AntiAbuse::IdentityVerification::Settings.arkose_client_secret
        }.compact.to_json
      end

      def error(response)
        ServiceResponse.error(message: "Unable to fetch authorization token. Response code: #{response.code}")
      end

      def success(token)
        ServiceResponse.success(payload: { token: token })
      end
    end
  end
end
