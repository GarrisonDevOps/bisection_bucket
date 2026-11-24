# frozen_string_literal: true

module ProtectedBranches
  class BaseService < ::BaseService
    RATE_LIMIT_KEY = :protected_branch_write

    attr_reader :project_or_group

    # current_user - The user that performs the action
    # params - A hash of parameters
    def initialize(project_or_group, current_user = nil, params = {})
      @project_or_group = project_or_group
      @current_user = current_user
      @params = params
    end

    def after_execute(*)
      # overridden in EE::ProtectedBranches module
    end

    def refresh_cache
      CacheService.new(@project_or_group, @current_user, @params).refresh
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e)
    end

    private

    # Create and delete share one counter; separate ones would double the budget.
    # The key is a staged_rule, so it only reports a block once
    # protected_branch_write_rate_limit_enforce is enabled for the namespace.
    def check_rate_limit!
      scope = { user: current_user, namespace: project_or_group.root_ancestor }
      return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: scope)

      raise ::RateLimitedService::RateLimitedError.new(
        key: RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
      ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
    end
  end
end

ProtectedBranches::BaseService.prepend_mod
