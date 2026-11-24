# frozen_string_literal: true

module Gitlab
  module Repositories
    # Limits pushes to one project per minute, counted across all users and
    # both protocols, before the pack is uploaded to Gitaly.
    module PushRateLimit
      KEY = :git_push_per_project
      MESSAGE = 'Too many pushes to this project. Try again later.'

      class << self
        def enabled?(project)
          project.present? && Feature.enabled?(:rate_limit_git_push_per_project, project)
        end

        def throttled?(request:, user:, project:)
          return false unless enabled?(project)

          Gitlab::ApplicationRateLimiter.throttled_request?(request, user, KEY, scope: { project: project })
        end

        def retry_after
          Gitlab::ApplicationRateLimiter.period_for(KEY)
        end
      end
    end
  end
end
