# frozen_string_literal: true

module Ci
  module Minutes
    class UpdateGitlabHostedRunnerMonthlyUsageService
      def initialize(root_namespace_id, project_id, runner_id, build_id, compute_minutes, duration)
        @root_namespace_id = root_namespace_id
        @project_id = project_id
        @runner_id = runner_id
        @build_id = build_id
        @compute_minutes = compute_minutes
        @duration = duration
      end

      def execute
        return unless Gitlab::Dedicated.feature_available?(:hosted_runners)

        track_monthly_usage
      end

      private

      def track_monthly_usage
        return unless valid_tracking_target?

        usage = GitlabHostedRunnerMonthlyUsage.find_or_create_current(
          root_namespace_id: @root_namespace_id,
          project_id: @project_id,
          runner_id: @runner_id
        )
        HostedRunnerIdempotencyCache.ensure_idempotency(@build_id) do
          usage.increase_usage(compute_minutes: @compute_minutes, duration: @duration)
        end

        ServiceResponse.success(
          message: "Successfully updated usage",
          payload: { usage: usage }
        )
      end

      def valid_tracking_target?
        # We don't track usage which can't be attributed to a namespace, runner or project
        # (Example: project was deleted while the build was finishing).
        # the billing source of truth is CustomerDot via runner logs
        # the visualiztion in gitlab is just an estimate for users
        # we could make these columns nullable in the future so we could
        # have a bucket of usage without associated namespaces, runners, or projects
        return false unless @root_namespace_id
        return false unless @project_id.present? && @runner_id.present?

        true
      end

      class HostedRunnerIdempotencyCache
        TTL = 12.hours

        def self.ensure_idempotency(build_id)
          cache_key = "gitlab_hosted_runner_usage:#{build_id}"

          ::IdempotencyCache.ensure_idempotency(cache_key, TTL) { yield }
        end
      end
    end
  end
end
