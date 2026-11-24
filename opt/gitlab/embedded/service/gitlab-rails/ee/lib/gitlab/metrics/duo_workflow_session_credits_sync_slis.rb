# frozen_string_literal: true

module Gitlab
  module Metrics
    # Error rate of the v2 session credits sync, one measurement per root namespace job.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/634230.
    module DuoWorkflowSessionCreditsSyncSlis
      include Gitlab::Metrics::SliConfig

      sidekiq_enabled!

      SLI_NAME = :duo_workflow_session_credits_sync

      class << self
        def initialize_slis!
          Gitlab::Metrics::Sli::ErrorRate.initialize_sli(SLI_NAME, [{}])
          initialize_freshness_histograms
        end

        def record(error:)
          Gitlab::Metrics::Sli::ErrorRate[SLI_NAME].increment(labels: {}, error: error)
        end

        private

        # The cron observes once per 6-hour tick, on any process. A series created by that
        # observation would already hold it, which increase() cannot see, so start at 0.
        def initialize_freshness_histograms
          freshness = ::Ai::DuoWorkflows::SessionCredits::SyncFreshness

          freshness.sync_age_histogram.get({})
          freshness.awaiting_sync_histogram.get({})
        end
      end
    end
  end
end
