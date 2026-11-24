# frozen_string_literal: true

module Ai
  module FlowSchedules
    class UpdateService
      include ::Services::ReturnServiceResponses

      def initialize(flow_schedule:, current_user:)
        @flow_schedule = flow_schedule
        @current_user = current_user
      end

      def execute(params)
        unless Ability.allowed?(@current_user, :update_ai_flow_schedule, @flow_schedule.project)
          return error('You are not authorized to manage flow schedules', :forbidden)
        end

        if params[:active] && !@flow_schedule.flow_trigger.active?
          return error('Turn on the flow trigger to activate its schedule', :bad_request)
        end

        if @flow_schedule.update(params)
          success(flow_schedule: @flow_schedule)
        else
          error(@flow_schedule.errors.full_messages.to_sentence, :bad_request)
        end
      end
    end
  end
end
