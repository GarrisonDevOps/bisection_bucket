# frozen_string_literal: true

module CloudConnector
  class ServiceAccessTokensStorageService
    def initialize(token, expires_at)
      @token = token
      @expires_at = expires_at
    end

    def execute
      if token && expires_at
        store_token
        cleanup_expired_tokens
      else
        cleanup_all_tokens
      end

      ServiceResponse.success
    rescue StandardError => err
      Gitlab::ErrorTracking.track_exception(err)

      ServiceResponse.error(message: err.message)
    end

    private

    attr_reader :token, :expires_at

    def store_token
      CloudConnector::ServiceAccessToken.create!(token: token, expires_at: expires_at_time)
      log_event({ action: 'created', expires_at: expires_at_time })
    end

    def expires_at_time
      if expires_at.is_a?(String)
        Time.iso8601(expires_at)
      elsif expires_at.is_a?(Numeric) && expires_at > 0
        Time.at(expires_at, in: '+00:00')
      end
    end

    def cleanup_expired_tokens
      CloudConnector::ServiceAccessToken.expired.delete_all
      log_event({ action: 'cleanup_expired' })
    end

    def cleanup_all_tokens
      CloudConnector::ServiceAccessToken.delete_all
      log_event({ action: 'cleanup_all' })
    end

    def log_event(log_fields)
      Gitlab::AppLogger.info(
        message: 'service_access_tokens',
        **log_fields
      )
    end
  end
end
