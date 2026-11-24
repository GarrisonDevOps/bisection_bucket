# frozen_string_literal: true

module Ci
  module PipelineSchedules
    class DestroyService
      include Gitlab::HandlesRemovalOf
      include Ci::PipelineScheduleRateLimitable

      # Ci::PipelineSchedule#destroy nullifies the schedule's pipelines in
      # batches before the row is deleted.
      handles_removal_of :p_ci_pipelines

      def initialize(schedule, user)
        @schedule = schedule
        @user = user
      end

      def execute
        throttled = rate_limited_response
        return forbidden unless allowed?
        return throttled if throttled

        if schedule.destroy
          ServiceResponse.success(payload: schedule)
        else
          ServiceResponse.error(message: _('Failed to remove the pipeline schedule'), payload: schedule)
        end
      end

      private

      attr_reader :schedule, :user

      def allowed?
        Ability.allowed?(user, :delete_pipeline_schedule, schedule)
      end

      def forbidden
        ServiceResponse.error(
          message: _('The current user is not authorized to delete the pipeline schedule'),
          reason: :forbidden,
          payload: schedule
        )
      end
    end
  end
end
