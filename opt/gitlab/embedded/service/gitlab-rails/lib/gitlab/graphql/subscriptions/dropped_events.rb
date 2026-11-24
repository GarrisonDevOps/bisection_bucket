# frozen_string_literal: true

module Gitlab
  module Graphql
    module Subscriptions
      module DroppedEvents
        def self.count(subscription, reason, events = 1)
          counter.increment({ subscription: subscription.to_s.underscore, reason: reason.to_s }, events)
        end

        def self.counter
          @counter ||= Gitlab::Metrics.counter(
            :gitlab_graphql_subscription_events_dropped_total,
            'Number of GraphQL subscription events dropped instead of triggered'
          )
        end
        private_class_method :counter
      end
    end
  end
end
