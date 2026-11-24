# frozen_string_literal: true

module GitlabSubscriptions
  class CreateHandRaiseLeadService
    RATE_LIMIT_KEY = :hand_raise_lead_create

    def initialize(user:)
      @user = user
    end

    def execute(params)
      return rate_limited_error if rate_limited?

      response = client.generate_lead(params)

      if response[:success]
        ServiceResponse.success
      else
        ServiceResponse.error(message: response.dig(:data, :errors))
      end
    end

    private

    attr_reader :user

    def rate_limited?
      return false unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: user })

      log_rate_limited

      Feature.enabled?(:enforce_hand_raise_lead_rate_limit, user)
    end

    def log_rate_limited
      Gitlab::AuthLogger.error(
        message: 'Application_Rate_Limiter_Request',
        env: :"#{RATE_LIMIT_KEY}_request_limit",
        user_id: user.id,
        username: user.username
      )
    end

    def rate_limited_error
      ServiceResponse.error(message: Gitlab::ApplicationRateLimiter.throttled_error_message, reason: :rate_limited)
    end

    def client
      Gitlab::SubscriptionPortal::Client
    end
  end
end
