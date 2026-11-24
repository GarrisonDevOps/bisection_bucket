# frozen_string_literal: true

require 'json'
require 'faraday'
require_relative '../azure_environment'

module AzIdentity
  module Identity
    class BaseClient
      include AzIdentity::AzureEnvironment

      class FetchCredentialsError < RuntimeError
      end

      DEFAULT_TIMEOUT_S = 30

      attr_accessor :credentials

      def initialize
        @mutex = Mutex.new
      end

      def fetch_credentials
        raise NotImplementedError
      end

      def fetch_credentials_if_needed
        # Serialize refreshes so concurrent callers (for example pooled Redis
        # connections across threads) don't each hit the token endpoint.
        @mutex.synchronize do
          @credentials = fetch_credentials if @credentials.nil? || refresh_needed?

          credentials
        end
      end

      def refresh_needed?
        return true unless @credentials

        @credentials.refresh_needed?
      end

      protected

      def process_token_response(response)
        raise FetchCredentialsError, response.to_s unless response.success?

        body = ::JSON.parse(response.body)
        access_token = body['access_token']

        return unless access_token

        Credentials.new(access_token, expiration_time(body))
      rescue ::JSON::ParserError
        nil
      end

      # IMDS (managed identity) returns an absolute epoch in +expires_on+, while
      # the Microsoft Entra v2.0 token endpoint (workload identity) returns a
      # relative +expires_in+ in seconds. Returns nil when neither is present,
      # which Credentials treats as "expiry unknown, always refresh".
      def expiration_time(body)
        if (expires_on = body['expires_on'])
          ::Time.at(expires_on.to_i)
        elsif (expires_in = body['expires_in'])
          ::Time.now + expires_in.to_i
        end
      end

      private

      def get(url, params: nil, headers: nil)
        Faraday.get(url, params, headers) do |req|
          req.options.timeout = DEFAULT_TIMEOUT_S
        end
      rescue ::Faraday::Error => e
        raise FetchCredentialsError, e.to_s
      end

      def post(url, body: nil, headers: nil)
        Faraday.post(url, body, headers) do |req|
          req.options.timeout = DEFAULT_TIMEOUT_S
        end
      rescue ::Faraday::Error => e
        raise FetchCredentialsError, e.to_s
      end
    end
  end
end
