# frozen_string_literal: true

module Issuables
  class ScheduleCsvExportService
    RATE_LIMIT_KEY = :issuable_csv_export

    def initialize(type:, current_user:, project:, params:)
      @type = type
      @current_user = current_user
      @project = project
      @params = params
    end

    def execute
      check_rate_limit!

      IssuableExportCsvWorker.perform_async(type, current_user.id, project.id, params)

      nil
    end

    private

    attr_reader :type, :current_user, :project, :params

    def check_rate_limit!
      return unless ::Feature.enabled?(:issuable_csv_export_rate_limit, current_user)
      return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })

      raise ::RateLimitedService::RateLimitedError.new(
        key: RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
      ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
    end
  end
end
