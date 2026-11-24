# frozen_string_literal: true

module Dora
  module Watchers
    class DeploymentWatcher
      def self.mount(klass)
        klass.state_machine :status do
          after_transition any => :success do |deployment|
            # LinkMergeRequestWorker refreshes the metrics once linking is done.
            next if Feature.enabled?(:dora_metrics_refresh_once_per_deployment, deployment.project)

            Dora::Watchers.process_event(deployment, :successful)
          end
        end
      end

      attr_reader :deployment, :event

      def initialize(deployment, event)
        @deployment = deployment
        @event = event
      end

      def process
        env_id = deployment.environment_id
        refresh_date = deployment.finished_at.to_date.iso8601
        project = deployment.project
        refresh_once = Feature.enabled?(:dora_metrics_refresh_once_per_deployment, project)

        deployment.run_after_commit_or_now do
          Gitlab::ApplicationContext.with_context(project: project, organization: project.organization) do
            if refresh_once
              # Only LinkMergeRequestWorker calls this now, after linking, so no delay is needed.
              ::Dora::DailyMetrics::RefreshWorker.perform_async(env_id, refresh_date)
            else
              # Schedule to refresh the DORA daily metrics.
              # It has 5 minutes delay due to waiting for the other async processes
              # (e.g. `LinkMergeRequestWorker`) to be finished before collecting metrics.
              ::Dora::DailyMetrics::RefreshWorker.perform_in(5.minutes, env_id, refresh_date)
            end
          end
        end
      end
    end
  end
end
