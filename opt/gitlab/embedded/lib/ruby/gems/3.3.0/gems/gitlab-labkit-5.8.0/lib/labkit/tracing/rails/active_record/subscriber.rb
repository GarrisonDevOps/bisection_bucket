# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActiveRecord
        # ActiveRecord bridges active record notifications to
        # the distributed tracing subsystem
        class Subscriber
          include Labkit::Tracing::TracingCommon

          ACTIVE_RECORD_NOTIFICATION_TOPIC = "sql.active_record"

          # Instruments Rails ActiveRecord events for opentracing.
          # Returns a lambda, which, when called will unsubscribe from the notifications
          def self.instrument
            subscription = ::ActiveSupport::Notifications.subscribe(ACTIVE_RECORD_NOTIFICATION_TOPIC, SqlInstrumenter.new)

            create_unsubscriber [subscription]
          end
        end
      end
    end
  end
end
