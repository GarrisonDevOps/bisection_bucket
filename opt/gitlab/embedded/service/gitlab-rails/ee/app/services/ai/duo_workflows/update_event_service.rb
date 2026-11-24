# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class UpdateEventService
      include ::Services::ReturnServiceResponses

      def initialize(event:, params:)
        @event = event
        @params = params
      end

      def execute
        return error(@event.errors.full_messages, :bad_request) unless @event.update(@params)

        success(event: @event)
      end
    end
  end
end
