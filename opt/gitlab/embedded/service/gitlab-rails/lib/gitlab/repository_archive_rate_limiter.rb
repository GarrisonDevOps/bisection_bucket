# frozen_string_literal: true

module Gitlab
  module RepositoryArchiveRateLimiter
    def archive_rate_limit_reached?(current_user, project)
      return false unless Feature.enabled?(:archive_rate_limit)

      cross_project_rate_limit_reached?(current_user) ||
        per_project_rate_limit_reached?(current_user, project)
    end

    def check_archive_rate_limit!(current_user, project, &block)
      return unless Feature.enabled?(:archive_rate_limit)

      check_cross_project_archive_rate_limit!(current_user, &block)
      return if respond_to?(:performed?) && performed?

      check_per_project_archive_rate_limit!(current_user, project, &block)
    end

    private

    def cross_project_rate_limit_reached?(current_user)
      if current_user
        Gitlab::ApplicationRateLimiter.throttled_request?(
          request, current_user, :repositories_archive,
          scope: { user: current_user }, peek: true)
      else
        Gitlab::ApplicationRateLimiter.throttled_request?(
          request, current_user, :repositories_archive_unauthenticated,
          scope: { ip: request.ip }, peek: true)
      end
    end

    def per_project_rate_limit_reached?(current_user, project)
      threshold = current_user ? nil : 100

      Gitlab::ApplicationRateLimiter.throttled_request?(
        request, current_user, :project_repositories_archive,
        scope: { project: project, user: current_user }, threshold: threshold, peek: true)
    end

    def check_cross_project_archive_rate_limit!(current_user, &block)
      if current_user
        check_rate_limit!(:repositories_archive, scope: { user: current_user }, &block)
      else
        check_rate_limit!(:repositories_archive_unauthenticated, scope: { ip: request.ip }, &block)
      end
    end

    def check_per_project_archive_rate_limit!(current_user, project, &block)
      threshold = current_user ? nil : 100

      check_rate_limit!(:project_repositories_archive,
        scope: { project: project, user: current_user }, threshold: threshold, &block)
    end
  end
end
