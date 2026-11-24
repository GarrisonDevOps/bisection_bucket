# frozen_string_literal: true

module Mutations
  module AuditEvents
    # One per-user limit shared by the group destination create and update mutations. Over-limit calls
    # are logged to auth_json.log and only blocked when enforce_audit_streaming_destination_limits is on.
    module DestinationRateLimitable
      extend ActiveSupport::Concern

      RATE_LIMIT_KEY = :audit_event_streaming_destination_mutation

      private

      def destination_rate_limited?(group)
        request = context[:request]
        throttled = if request
                      ::Gitlab::ApplicationRateLimiter.throttled_request?(
                        request, current_user, RATE_LIMIT_KEY, scope: { user: current_user }
                      )
                    else
                      ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })
                        .tap { |limited| log_throttled_without_request if limited }
                    end

        throttled && ::Feature.enabled?(:enforce_audit_streaming_destination_limits, group)
      end

      # GraphqlChannel and MCP tools build a context without `request`, so throttled_request? can't log them.
      def log_throttled_without_request
        ::Gitlab::AuthLogger.error(
          message: 'Application_Rate_Limiter_Request',
          env: :"#{RATE_LIMIT_KEY}_request_limit",
          Labkit::Fields::GL_USER_ID => current_user.id,
          Labkit::Fields::GL_USER_NAME => current_user.username
        )
      end

      def destination_rate_limited_response
        { errors: [::Gitlab::ApplicationRateLimiter.throttled_error_message] }
      end
    end
  end
end
