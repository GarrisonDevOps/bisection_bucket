# frozen_string_literal: true

module Ci
  # One per-user allowance shared by every pipeline schedule management action
  # (create, update, delete, take ownership), so alternating actions cannot
  # multiply it. The attempt is counted before the access check so a rejected
  # call still costs an attempt, but the access error is returned first so the
  # caller keeps the real reason, as in Ci::RetryPipelineService. Including
  # services expose `user` and `schedule`.
  module PipelineScheduleRateLimitable
    include Gitlab::Utils::StrongMemoize

    RATE_LIMIT_KEY = :pipeline_schedule_management

    private

    # Returns a throttled ServiceResponse, or nil when the call may proceed.
    # Memoized so a service that checks before and after `super` counts once.
    def rate_limited_response
      return unless Feature.enabled?(:rate_limit_pipeline_schedule_management, schedule.project)
      return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: user })

      log_rate_limited

      ServiceResponse.error(
        message: ::Gitlab::ApplicationRateLimiter.throttled_error_message,
        reason: :rate_limited,
        payload: schedule
      )
    end
    strong_memoize_attr :rate_limited_response

    def log_rate_limited
      Gitlab::AppJsonLogger.info(
        Labkit::Fields::CLASS_NAME => self.class.to_s,
        message: 'Pipeline schedule management rate limit exceeded',
        rate_limit: RATE_LIMIT_KEY.to_s,
        Labkit::Fields::GL_PROJECT_ID => schedule.project_id,
        Labkit::Fields::GL_USER_ID => user.id,
        **{ pipeline_schedule_id: schedule.id }.compact,
        **Gitlab::ApplicationContext.current
      )
    end
  end
end
