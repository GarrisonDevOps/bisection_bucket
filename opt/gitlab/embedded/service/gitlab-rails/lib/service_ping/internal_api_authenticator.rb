# frozen_string_literal: true

module ServicePing
  module InternalApiAuthenticator
    include ::Gitlab::JwtAuthenticatable

    API_HEADER = 'Gitlab-Service-Ping-Api-Request'
    JWT_ISSUER = 'gitlab-service-ping'
    JWT_AUDIENCE = 'gitlab'
    EXPIRATION = 5.minutes
    CLOCK_SKEW = 30.seconds

    class << self
      # Returns the token payload, whose `sub` names the calling service, or nil.
      def verify_api_request(request_headers)
        token = request_headers[API_HEADER]
        return if token.blank?

        payload, _header = decode_jwt(
          token,
          issuer: JWT_ISSUER,
          audience: JWT_AUDIENCE,
          iat_after: Time.current - EXPIRATION,
          iat_leeway: CLOCK_SKEW
        )

        payload if payload['sub'].present?
      rescue JWT::DecodeError, Errno::ENOENT
        nil
      # A malformed secret file (invalid base64 or wrong length from read_secret) raises
      # ArgumentError/RuntimeError. Fail closed with 401, but log so a corrupted secret is
      # not silently mistaken for a stream of bad tokens.
      rescue ArgumentError, RuntimeError => e
        Gitlab::AppLogger.warn(
          Labkit::Fields::LOG_MESSAGE => "Could not read Service Ping internal API secret file at #{secret_path}",
          Labkit::Fields::ERROR_TYPE => e.class.name,
          Labkit::Fields::ERROR_MESSAGE => e.message
        )
        nil
      end

      def secret_path
        Gitlab.config.service_ping.secret_file
      end

      def ensure_secret!
        return if File.exist?(secret_path)

        write_secret
      rescue Errno::EACCES, Errno::EPERM, Errno::EROFS, Errno::ENOENT => e
        Gitlab::AppLogger.warn(
          Labkit::Fields::LOG_MESSAGE => "Could not write Service Ping internal API secret file at #{secret_path}",
          Labkit::Fields::ERROR_TYPE => e.class.name,
          Labkit::Fields::ERROR_MESSAGE => e.message
        )
      end
    end
  end
end
