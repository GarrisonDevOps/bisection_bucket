# frozen_string_literal: true

module Search
  module Zoekt
    # Indexes a project that has no Zoekt repository when its code search falls back.
    # Skips the WriteAheadLog indicator so a waiting searcher isn't held by a WAL archive backlog.
    class FallbackIndexingTaskWorker
      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      data_consistency :delayed
      idempotent!
      urgency :low
      deduplicate :until_executed, if_deduplicated: :reschedule_once

      concurrency_limit -> { 100 }

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes,
        indicators: [
          ::Gitlab::Database::HealthStatus::Indicators::AutovacuumActiveOnTable,
          ::Gitlab::Database::HealthStatus::Indicators::PatroniApdex,
          ::Gitlab::Database::HealthStatus::Indicators::WalRate
        ]

      def perform(project_id)
        return false unless ::Search::Zoekt.licensed_and_indexing_enabled?

        IndexingTaskService.execute(project_id, :index_repo)
      end
    end
  end
end
