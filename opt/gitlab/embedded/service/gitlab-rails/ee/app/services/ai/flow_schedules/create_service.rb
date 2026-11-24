# frozen_string_literal: true

module Ai
  module FlowSchedules
    class CreateService
      include ::Services::ReturnServiceResponses

      def initialize(flow_trigger:, current_user:)
        @flow_trigger = flow_trigger
        @current_user = current_user
      end

      def execute(params)
        unless Feature.enabled?(:ai_flow_schedules, @flow_trigger.project)
          return error('Flow schedules are not available', :forbidden)
        end

        unless Ability.allowed?(@current_user, :create_ai_flow_schedule, @flow_trigger.project)
          return error('You are not authorized to manage flow schedules', :forbidden)
        end

        unless @flow_trigger.scheduled_triggers_beta_available?
          return error('Scheduled automations require experiment and beta features', :forbidden)
        end

        unless @flow_trigger.container&.duo_scheduled_triggers_enabled
          return error('Scheduled automations are turned off', :forbidden)
        end

        schedule = @flow_trigger.flow_schedules.build(
          project: @flow_trigger.project,
          **params
        )

        if schedule.save
          success(flow_schedule: schedule)
        else
          error(schedule.errors.full_messages.to_sentence, :bad_request)
        end
      end
    end
  end
end
