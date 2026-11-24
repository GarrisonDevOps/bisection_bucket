# frozen_string_literal: true

module RedisCloudAuth
  module Providers
    # Google Cloud provider for Memorystore for Redis Cluster / Valkey IAM
    # authentication. The Redis password is a Google OAuth2 access token; the
    # identity needs the `roles/redis.dbConnectionUser` role.
    #
    # Uses Application Default Credentials (the `googleauth` gem), so it picks up
    # GKE Workload Identity, the GCE/GKE metadata server, or a service-account
    # key automatically, with no key material in the descriptor.
    #
    # Descriptor keys:
    #   :username    Redis AUTH username (defaults to "default"; Memorystore
    #                verifies the token and ignores the username, confirmed live:
    #                token-only, "default", and the SA email all authenticate)
    #   :scope       OAuth scope(s) (defaults to cloud-platform)
    #   :credentials optional prebuilt googleauth/Signet credentials object
    #
    # Implements the common interface: #call => [username, token],
    # #expires_at => Time.
    #
    # NOTE: Memorystore keeps an already-authenticated connection alive even
    # after its token expires, so for GCP the connect-time token (TokenCredential)
    # is the load-bearing part; the re-auth middleware is harmless but less
    # critical than on providers that drop the connection at expiry.
    class GCP
      DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
      DEFAULT_USERNAME = "default"
      REFRESH_MARGIN = 60

      def self.build(descriptor)
        new(descriptor)
      end

      def initialize(descriptor)
        @username = descriptor[:username] || DEFAULT_USERNAME
        @scope = descriptor[:scope] || DEFAULT_SCOPE
        @credentials = descriptor[:credentials]
        @mutex = Mutex.new
      end

      def call
        @mutex.synchronize do
          creds = credentials
          creds.fetch_access_token! if creds.access_token.nil? || creds.expires_within?(REFRESH_MARGIN)
          [@username, creds.access_token]
        end
      end

      def expires_at
        @mutex.synchronize { @credentials&.expires_at }
      end

      private

      def credentials
        @credentials ||= begin
          require "googleauth"
          Google::Auth.get_application_default(Array(@scope))
        end
      end
    end
  end
end
