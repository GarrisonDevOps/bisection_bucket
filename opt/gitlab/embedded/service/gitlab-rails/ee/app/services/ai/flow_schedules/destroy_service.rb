# frozen_string_literal: true

module Ai
  module FlowSchedules
    class DestroyService
      include ::Services::ReturnServiceResponses

      def initialize(flow_schedule:, current_user:)
        @flow_schedule = flow_schedule
        @current_user = current_user
      end

      def execute
        unless Ability.allowed?(@current_user, :delete_ai_flow_schedule, @flow_schedule.project)
          return error('You are not authorized to manage flow schedules', :forbidden)
        end

        if @flow_schedule.destroy
          success(flow_schedule: @flow_schedule)
        else
          error(@flow_schedule.errors.full_messages.to_sentence, :bad_request)
        end
      end
    end
  end
end
