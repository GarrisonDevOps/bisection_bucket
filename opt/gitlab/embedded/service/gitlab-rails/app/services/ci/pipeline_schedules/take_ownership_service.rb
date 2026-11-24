# frozen_string_literal: true

module Ci
  module PipelineSchedules
    class TakeOwnershipService
      include Ci::PipelineScheduleRateLimitable

      def initialize(schedule, user)
        @schedule = schedule
        @user = user
      end

      def execute
        throttled = rate_limited_response
        return forbidden unless allowed?
        return throttled if throttled

        if schedule.update(owner: user)
          ServiceResponse.success(payload: schedule)
        else
          ServiceResponse.error(message: schedule.errors.full_messages)
        end
      end

      private

      attr_reader :schedule, :user

      def allowed?
        Ability.allowed?(user, :admin_pipeline_schedule, schedule)
      end

      def forbidden
        ServiceResponse.error(message: _('Failed to change the owner'), reason: :access_denied)
      end
    end
  end
end
