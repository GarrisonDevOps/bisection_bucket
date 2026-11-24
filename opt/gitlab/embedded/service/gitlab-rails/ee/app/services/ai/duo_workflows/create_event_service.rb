# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CreateEventService
      include ::Services::ReturnServiceResponses

      def initialize(workflow:, params:)
        @params = params
        @workflow = workflow
      end

      def execute
        event = @workflow.events.new(event_attributes)

        return error(event.errors.full_messages, :bad_request) unless event.save

        success(event: event)
      end

      def event_attributes
        @params.merge(workflow: @workflow)
      end
    end
  end
end
