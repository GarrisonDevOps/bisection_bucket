# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Destinations
      # The response body is deliberately left out: it is customer data and
      # the message ends up in logs and Sentry.
      class DestinationError < StandardError
        attr_reader :status

        def initialize(status)
          @status = status
          super("Destination responded with HTTP #{status}")
        end
      end
    end
  end
end
