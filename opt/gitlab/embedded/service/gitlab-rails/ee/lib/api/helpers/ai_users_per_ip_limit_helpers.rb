# frozen_string_literal: true

module API
  module Helpers
    module AiUsersPerIpLimitHelpers
      def check_ai_users_per_ip_limit!
        limit = ::Ai::UsersPerIpLimit.new(user: current_user, request: request)
        return unless limit.throttled?

        yield if block_given?

        header['RateLimit-Name'] = ::Ai::UsersPerIpLimit::RATE_LIMIT_KEY.to_s

        too_many_requests!(
          { error: ::Gitlab::ApplicationRateLimiter.throttled_error_message },
          retry_after: limit.period
        )
      end
    end
  end
end
