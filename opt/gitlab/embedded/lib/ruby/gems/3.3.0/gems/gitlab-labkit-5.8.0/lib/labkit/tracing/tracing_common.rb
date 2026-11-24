# frozen_string_literal: true

require "active_support/concern"
require "active_support/notifications"

module Labkit
  module Tracing
    # TracingCommon is a mixin for providing instrumentation
    # functionality for the instrumentation classes based on
    # ActiveSupport::Notifications
    module TracingCommon
      extend ::ActiveSupport::Concern

      class_methods do
        def create_unsubscriber(subscriptions)
          -> { subscriptions.each { |subscriber| ::ActiveSupport::Notifications.unsubscribe(subscriber) } }
        end
      end
    end
  end
end
