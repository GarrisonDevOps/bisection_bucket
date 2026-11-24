# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActiveSupport
        # ActiveSupport bridges action active support notifications to
        # the distributed tracing subsystem
        class Subscriber
          include Labkit::Tracing::TracingCommon

          CACHE_READ_TOPIC = "cache_read.active_support"
          CACHE_GENERATE_TOPIC = "cache_generate.active_support"
          CACHE_FETCH_HIT_TOPIC = "cache_fetch_hit.active_support"
          CACHE_WRITE_TOPIC = "cache_write.active_support"
          CACHE_DELETE_TOPIC = "cache_delete.active_support"

          # Instruments Rails ActiveSupport events for opentracing.
          # Returns a lambda, which, when called will unsubscribe from the notifications
          def self.instrument
            subscriptions = [
              ::ActiveSupport::Notifications.subscribe(CACHE_READ_TOPIC, CacheReadInstrumenter.new),
              ::ActiveSupport::Notifications.subscribe(CACHE_GENERATE_TOPIC, CacheGenerateInstrumenter.new),
              ::ActiveSupport::Notifications.subscribe(CACHE_FETCH_HIT_TOPIC, CacheFetchHitInstrumenter.new),
              ::ActiveSupport::Notifications.subscribe(CACHE_WRITE_TOPIC, CacheWriteInstrumenter.new),
              ::ActiveSupport::Notifications.subscribe(CACHE_DELETE_TOPIC, CacheDeleteInstrumenter.new),
            ]

            create_unsubscriber subscriptions
          end
        end
      end
    end
  end
end
