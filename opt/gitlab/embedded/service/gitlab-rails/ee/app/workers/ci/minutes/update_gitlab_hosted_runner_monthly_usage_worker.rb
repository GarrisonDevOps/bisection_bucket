# frozen_string_literal: true

module Ci
  module Minutes
    class UpdateGitlabHostedRunnerMonthlyUsageWorker
      include ApplicationWorker
      include PipelineBackgroundQueue

      urgency :low
      data_consistency :sticky

      sidekiq_options retry: 3

      idempotent! # IdempotencyCache handles this when retries are under 3

      def perform(namespace_id, params = {})
        project_id = params['project_id']
        runner_id = params['runner_id']
        build_id = params['build_id']
        compute_minutes = params['compute_minutes']
        duration = params['duration']

        ::Ci::Minutes::UpdateGitlabHostedRunnerMonthlyUsageService.new(
          namespace_id, project_id, runner_id, build_id, compute_minutes, duration
        ).execute
      end
    end
  end
end
