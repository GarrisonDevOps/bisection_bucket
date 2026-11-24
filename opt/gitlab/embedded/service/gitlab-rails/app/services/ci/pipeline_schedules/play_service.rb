# frozen_string_literal: true

module Ci
  module PipelineSchedules
    class PlayService < BaseService
      include Services::ReturnServiceResponses

      # The limit is counted before the access check so a denied call still
      # consumes the attempt; the access error is still returned first.
      def execute(schedule)
        throttled_response = check_rate_limit(schedule)

        check_access!(schedule)

        return throttled_response if throttled_response

        if !project.persisted? || project.self_or_ancestors_archived?
          return error("Failed to schedule pipeline.",
            :bad_request)
        end

        job_id = RunPipelineScheduleWorker.perform_async(schedule.id, current_user&.id)
        return error("Unable to schedule a pipeline to run immediately.", :internal_server_error) unless job_id

        success(job_id: job_id)
      end

      private

      def check_access!(schedule)
        raise Gitlab::Access::AccessDeniedError unless can?(current_user, :play_pipeline_schedule, schedule)
      end

      # Returns a throttled ServiceResponse, or nil when the call may proceed.
      def check_rate_limit(schedule)
        return unless current_user

        return unless ::Gitlab::ApplicationRateLimiter.throttled?(
          :play_pipeline_schedule, scope: { user: current_user, ci_pipeline_schedule: schedule }
        )

        log_rate_limited(schedule)

        ServiceResponse.error(
          message: _('You cannot play this scheduled pipeline at the moment. Please wait a minute.'),
          reason: :rate_limited
        )
      end

      def log_rate_limited(schedule)
        Gitlab::AppJsonLogger.info(
          Labkit::Fields::CLASS_NAME => self.class.to_s,
          message: 'Pipeline schedule play rate limit exceeded',
          rate_limit: 'play_pipeline_schedule',
          Labkit::Fields::GL_PROJECT_ID => schedule.project_id,
          Labkit::Fields::GL_USER_ID => current_user.id,
          pipeline_schedule_id: schedule.id,
          **Gitlab::ApplicationContext.current
        )
      end
    end
  end
end
