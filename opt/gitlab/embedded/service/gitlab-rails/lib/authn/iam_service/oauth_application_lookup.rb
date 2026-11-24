# frozen_string_literal: true

module Authn
  module IamService
    # Resolves client ids with no local application through IAM, for one page
    # render. The first failure stops further calls so a slow IAM cannot stall it.
    class OauthApplicationLookup
      include Gitlab::Loggable

      TIMEOUT_SECONDS = 2
      MAX_RUNTIME = 3.seconds
      CACHE_TTL = 10.minutes

      # IAM answers NOT_FOUND for a missing client, so a reply without one is a
      # bug, not an absence: the row becomes a placeholder, never a not-found.
      EmptyResponseError = Class.new(StandardError)

      def self.cache_key(client_id)
        ['authn', 'iam_service', 'oauth_application', client_id]
      end

      def initialize(client: GrpcClient.new(timeout: TIMEOUT_SECONDS, report_transient_errors: false))
        @client = client
        @limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        @unavailable = false
      end

      # Returns a RemoteOauthApplication, nil when IAM has no such client, or a
      # placeholder when IAM could not answer in time.
      def find(client_id)
        cached = Rails.cache.read(self.class.cache_key(client_id))
        return RemoteOauthApplication.new(**cached.slice(*RemoteOauthApplication.members)) if cached
        return RemoteOauthApplication.placeholder(client_id) if @unavailable || @limiter.over_time?

        application = fetch(client_id)
        remember(client_id, application) unless application.nil? || application.placeholder?
        application
      end

      private

      def fetch(client_id)
        client = @client.get_oauth_application(client_id: client_id).client
        raise EmptyResponseError, 'IAM returned no client' if client.nil? || client.client_id.blank?

        RemoteOauthApplication.from_managed_client(client)
      rescue GrpcClient::RequestError => e
        return if e.reason == :not_found

        give_up(client_id, e)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, client_id: client_id)
        give_up(client_id, e)
      end

      # A cache that cannot be written must not look like an IAM failure.
      def remember(client_id, application)
        Rails.cache.write(self.class.cache_key(client_id), application.to_h, expires_in: CACHE_TTL)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, client_id: client_id)
      end

      def give_up(client_id, error)
        @unavailable = true

        Gitlab::AuthLogger.error(
          build_structured_payload_labkit(
            message: 'IAM OAuth application lookup failed',
            client_id: client_id,
            Labkit::Fields::ERROR_TYPE => GrpcClient.error_label(error),
            Labkit::Fields::ERROR_MESSAGE => error.message
          )
        )

        RemoteOauthApplication.placeholder(client_id)
      end
    end
  end
end
