# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActionView
        # ActionView bridges action view notifications to
        # the distributed tracing subsystem
        class Subscriber
          include Labkit::Tracing::TracingCommon

          RENDER_TEMPLATE_NOTIFICATION_TOPIC = "render_template.action_view"
          RENDER_COLLECTION_NOTIFICATION_TOPIC = "render_collection.action_view"
          RENDER_PARTIAL_NOTIFICATION_TOPIC = "render_partial.action_view"

          # Instruments Rails ActionView events for opentracing.
          # Returns a lambda, which, when called will unsubscribe from the notifications
          def self.instrument
            subscriptions = [
              ::ActiveSupport::Notifications.subscribe(RENDER_TEMPLATE_NOTIFICATION_TOPIC, RenderTemplateInstrumenter.new),
              ::ActiveSupport::Notifications.subscribe(RENDER_COLLECTION_NOTIFICATION_TOPIC, RenderCollectionInstrumenter.new),
              ::ActiveSupport::Notifications.subscribe(RENDER_PARTIAL_NOTIFICATION_TOPIC, RenderPartialInstrumenter.new),
            ]

            create_unsubscriber subscriptions
          end
        end
      end
    end
  end
end
