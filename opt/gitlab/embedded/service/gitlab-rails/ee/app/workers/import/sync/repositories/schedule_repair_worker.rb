# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Requests a data-repair reconciliation pass for one synced repository.
      class ScheduleRepairWorker
        include ApplicationWorker

        data_consistency :sticky
        feature_category :importers
        urgency :low
        idempotent!
        deduplicate :until_executed, including_scheduled: true
        defer_on_database_health_signal :gitlab_main_org, [:import_sync_repository_states], 1.minute
        concurrency_limit -> { Gitlab::CurrentSettings.import_jobs_concurrency_limit }

        def perform(repository_id)
          repository = Import::Sync::Repository.find_by_id(repository_id)
          return unless repository

          # A repair is not a provider event, so it must not advance last_event_at.
          RequestUpdateService.new(repository, event_at: nil).execute
        rescue Errors::InactiveAuthorityError
          ::Gitlab::GithubImport::Logger.info(
            message: 'skipping scheduled repair, GitHub updates are not active',
            import_sync_repository_id: repository_id
          )
        end
      end
    end
  end
end
