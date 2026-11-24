# frozen_string_literal: true

module Gitlab
  module Graphql
    module Subscriptions
      # The rate limit a subscription declares with `rate_limit`. Each trigger is one event against the limit,
      # and `scope` gets the trigger's arguments and object.
      class RateLimitPolicy
        def initialize(key, scope)
          @key = key
          @scope = scope
        end

        # Counts the event against the budget.
        def throttled?(args, object)
          Gitlab::ApplicationRateLimiter.throttled?(key, scope: scope.call(args, object))
        end

        # Reads the budget without counting the event.
        def exhausted?(args, object)
          Gitlab::ApplicationRateLimiter.peek(key, scope: scope.call(args, object))
        end

        private

        attr_reader :key, :scope
      end
    end
  end
end
