# frozen_string_literal: true

module Gitlab
  module Graphql
    module Subscriptions
      # `outcome` is what the coalescer did with an update: `run` and `overflow` ran it at once, `deferred`
      # merged it, and `flushed` ran a merged update when its window ended.
      module CoalescedEvents
        def self.count(subscription, outcome)
          counter.increment({ subscription: subscription.to_s.underscore, outcome: outcome.to_s })
        end

        def self.counter
          @counter ||= Gitlab::Metrics.counter(
            :gitlab_graphql_subscription_coalesced_events_total,
            'Number of GraphQL subscription updates handled by the coalescer on the websocket nodes'
          )
        end
        private_class_method :counter
      end
    end
  end
end
