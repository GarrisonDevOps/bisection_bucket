# frozen_string_literal: true

module Mutations
  module Analytics
    module CustomDashboards
      # Shared per-user rate limit for the mutations that write a dashboard
      # config: create, and update when the request carries a config.
      module WriteRateLimitable
        extend ActiveSupport::Concern

        RATE_LIMIT_KEY = :custom_dashboard_write

        private

        def write_throttled?
          return false unless ::Feature.enabled?(:custom_dashboard_write_limits, current_user)

          request = context[:request]
          scope = { user: current_user }
          return ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: scope) unless request

          ::Gitlab::ApplicationRateLimiter.throttled_request?(request, current_user, RATE_LIMIT_KEY, scope: scope)
        end

        def rate_limited_response
          { dashboard: nil, errors: [::Gitlab::ApplicationRateLimiter.throttled_error_message] }
        end
      end
    end
  end
end
