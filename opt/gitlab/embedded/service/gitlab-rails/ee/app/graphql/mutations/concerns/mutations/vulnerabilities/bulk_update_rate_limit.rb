# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    module BulkUpdateRateLimit
      private

      def bulk_update_rate_limited?(keys)
        # Check every key so each window counts the call, even when an earlier one is already exceeded.
        keys.map { |key| bulk_update_throttled?(key) }.any?
      end

      def bulk_update_throttled?(key)
        scope = { user: current_user }
        request = context[:request]

        # Absent on non-HTTP entry points such as GraphqlChannel. Still count
        # those, just without the auth log entry and the bypass header.
        return ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: scope) unless request

        ::Gitlab::ApplicationRateLimiter.throttled_request?(request, current_user, key, scope: scope)
      end
    end
  end
end
