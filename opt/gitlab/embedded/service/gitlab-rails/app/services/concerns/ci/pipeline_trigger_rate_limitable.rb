# frozen_string_literal: true

module Ci
  # One per-user allowance shared by every pipeline trigger token management
  # action (create, update, delete), so alternating actions cannot multiply
  # it. The attempt is counted before the access check so a rejected call
  # still costs an attempt, but the access error is returned first so the
  # caller keeps the real reason, as in Ci::RetryPipelineService. Including
  # services expose `current_user`.
  module PipelineTriggerRateLimitable
    RATE_LIMIT_KEY = :pipeline_trigger_management

    private

    # Returns a throttled ServiceResponse, or nil when the call may proceed.
    def rate_limited_response(project, trigger: nil, payload: {})
      return unless current_user
      return unless Feature.enabled?(:rate_limit_pipeline_trigger_management, project)
      return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })

      log_rate_limited(project, trigger)

      ServiceResponse.error(
        message: ::Gitlab::ApplicationRateLimiter.throttled_error_message,
        reason: :rate_limited,
        payload: payload
      )
    end

    def log_rate_limited(project, trigger)
      Gitlab::AppJsonLogger.info(
        Labkit::Fields::CLASS_NAME => self.class.to_s,
        message: 'Pipeline trigger token management rate limit exceeded',
        rate_limit: RATE_LIMIT_KEY.to_s,
        Labkit::Fields::GL_PROJECT_ID => project.id,
        Labkit::Fields::GL_USER_ID => current_user.id,
        **{ trigger_id: trigger&.id }.compact,
        **Gitlab::ApplicationContext.current
      )
    end
  end
end
