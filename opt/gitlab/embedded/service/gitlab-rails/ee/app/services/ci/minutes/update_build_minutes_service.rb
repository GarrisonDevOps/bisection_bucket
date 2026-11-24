# frozen_string_literal: true

module Ci
  module Minutes
    class UpdateBuildMinutesService < BaseService
      include Gitlab::InternalEventsTracking

      def execute(build)
        return unless build.complete?
        return unless build.duration&.positive?

        runner = build.runner

        track_ci_build_minutes(build, runner)

        if runner&.dedicated_gitlab_hosted?
          update_dedicated_hosted_usage(build, runner)
        elsif build.shared_runner_build?
          update_instance_usage(build, runner)
        end
      end

      private

      def update_dedicated_hosted_usage(build, runner)
        dedicated_compute_minutes_consumption = ::Gitlab::Ci::Minutes::HostedRunners::Consumption
          .new(pipeline: build.pipeline, runner_matcher: runner.runner_matcher, duration: build.duration)
          .amount

        ::Ci::Minutes::UpdateGitlabHostedRunnerMonthlyUsageWorker.perform_async(
          namespace.id,
          {
            'project_id' => build.project_id,
            'runner_id' => build.runner_id,
            'build_id' => build.id,
            'compute_minutes' => dedicated_compute_minutes_consumption,
            'duration' => build.duration
          }
        )
      end

      def update_instance_usage(build, runner)
        instance_compute_minutes_consumption = ::Gitlab::Ci::Minutes::Consumption
          .new(pipeline: build.pipeline, runner_matcher: runner.runner_matcher, duration: build.duration)
          .amount

        ::Ci::Minutes::UpdateProjectAndNamespaceUsageWorker
          .perform_async(
            instance_compute_minutes_consumption,
            project.id,
            namespace.id,
            build.id,
            { 'duration' => build.duration }
          )
      end

      def namespace
        project.shared_runners_limit_namespace
      end

      def track_ci_build_minutes(build, runner)
        track_internal_event(
          "track_ci_build_minutes_with_runner_type",
          namespace: namespace,
          additional_properties: {
            label: runner&.runner_type&.to_s,
            value: (build.duration / 60).round(2)
          }
        )
      end
    end
  end
end
