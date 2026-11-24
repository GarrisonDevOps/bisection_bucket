# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      # Rate limits an AI Catalog GraphQL mutation by a key registered in the
      # application rate limiter, and logs throttled calls to the auth log
      # (`auth_json.log`) with the user and request, so hits can be counted per
      # user after rollout.
      #
      #   include ::Mutations::Ai::Catalog::RateLimitable
      #
      #   def resolve(**args)
      #     return { errors: [message] } if rate_limited?(:my_key, scope: { user: current_user })
      #     ...
      #   end
      module RateLimitable
        extend ActiveSupport::Concern

        private

        # @param key [Symbol] key registered in the application rate limiter
        # @param scope [Hash] the rate limit scope, for example `{ user: current_user }`
        # @return [Boolean] whether the call is over the limit
        def rate_limited?(key, scope:)
          request = context[:request]

          # Absent on non-HTTP entry points such as GraphqlChannel. Still count
          # those, just without the auth log entry and the bypass header.
          return ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: scope) unless request

          ::Gitlab::ApplicationRateLimiter.throttled_request?(request, current_user, key, scope: scope)
        end
      end
    end
  end
end
