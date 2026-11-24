# frozen_string_literal: true

module Gitlab
  module Geo
    module LogCursor
      module Events
        module BaseEvent
          def initialize(event, created_at, logger)
            @event = event
            @created_at = created_at
            @logger = logger
          end

          private

          attr_reader :event, :created_at, :logger

          def log_event(message, params = {})
            logger.event_info(
              created_at,
              message,
              params.merge(event_id: event.id)
            )
          end
        end
      end
    end
  end
end
