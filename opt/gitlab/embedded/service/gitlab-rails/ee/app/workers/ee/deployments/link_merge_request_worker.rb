# frozen_string_literal: true

module EE
  module Deployments
    module LinkMergeRequestWorker
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        include Sidekiq::InterruptionsExhausted

        # after_perform never runs when linking keeps failing or is interrupted, but the deployment still counts.
        sidekiq_retries_exhausted do |job, _exception|
          refresh_dora_metrics(job['args'].first)
        end

        sidekiq_interruptions_exhausted do |job|
          refresh_dora_metrics(job['args'].first)
        end
      end

      class_methods do
        def refresh_dora_metrics(deployment_id)
          deployment = ::Deployment.find_by_id(deployment_id)

          return unless deployment&.success?
          return unless ::Feature.enabled?(:dora_metrics_refresh_once_per_deployment, deployment.project)

          ::Dora::Watchers.process_event(deployment, :successful)
        end
      end

      override :after_perform
      def after_perform(deployment)
        return unless deployment.success?

        Dora::Watchers.process_event(deployment, :successful)
      end
    end
  end
end
