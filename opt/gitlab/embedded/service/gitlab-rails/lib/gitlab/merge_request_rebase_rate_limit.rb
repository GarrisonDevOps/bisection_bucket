# frozen_string_literal: true

module Gitlab
  # Shared by the merge request rebase entry points. Include it in a controller or
  # API endpoint that provides `current_user` and `check_rate_limit!` (CheckRateLimit
  # or API::Helpers::RateLimiter). Code without a request, such as quick actions,
  # calls `.throttled?` instead.
  module MergeRequestRebaseRateLimit
    KEY = :merge_requests_rebase

    def self.enabled?(user)
      Feature.enabled?(:merge_requests_rebase_rate_limit, user)
    end

    def self.throttled?(user)
      return false unless enabled?(user)

      Gitlab::ApplicationRateLimiter.throttled?(KEY, scope: { user: user })
    end

    def self.throttled_message
      _('Too many rebases have been requested. Try again later.')
    end

    def check_merge_request_rebase_rate_limit!(&block)
      return unless Gitlab::MergeRequestRebaseRateLimit.enabled?(current_user)

      check_rate_limit!(KEY, scope: { user: current_user }, &block)
    end
  end
end
