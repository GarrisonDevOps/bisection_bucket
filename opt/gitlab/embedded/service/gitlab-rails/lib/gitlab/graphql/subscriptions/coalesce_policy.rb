# frozen_string_literal: true

module Gitlab
  module Graphql
    module Subscriptions
      # The coalescing a subscription declares with `coalesce`: within `window`, updates about one record merge.
      class CoalescePolicy
        attr_reader :window

        def initialize(window)
          raise ArgumentError, 'window must be a positive duration' unless window.is_a?(Numeric) && window > 0

          @window = window
        end

        def enabled_for?(user)
          Feature.enabled?(:graphql_subscription_coalescing, user)
        end
      end
    end
  end
end
