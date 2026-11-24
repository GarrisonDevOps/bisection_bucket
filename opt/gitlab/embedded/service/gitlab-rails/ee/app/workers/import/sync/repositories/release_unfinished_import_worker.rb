# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Releases the sync repository of a GitHub import that failed or was canceled, so the project does not
      # stay read-only and nothing keeps targeting the row.
      class ReleaseUnfinishedImportWorker
        include ApplicationWorker

        RELEASABLE_STATES = %w[provisioning provider_canonical disconnected].freeze

        data_consistency :sticky
        feature_category :importers
        urgency :low
        idempotent!
        deduplicate :until_executed
        defer_on_database_health_signal :gitlab_main_org, [:import_sync_repositories], 1.minute

        def perform(project_id)
          project = Project.find_by_id(project_id)
          return if project.nil? || project.import_finished?

          sync_repository = project.import_sync_repository
          return unless sync_repository

          # Raises on a held lease so Sidekiq retries: a catch-up may flip the row to provider_canonical meanwhile.
          previous_state = CancelBootstrapService.new(sync_repository, from: RELEASABLE_STATES).execute
          log_released(project, sync_repository, previous_state) if previous_state

          enqueue_cleanup(project, sync_repository.reset)
        end

        private

        # Checked on every run, not only after the move, so a lost enqueue is recovered by a retry.
        # The cleanup deletes the webhook before the token it needs.
        def enqueue_cleanup(project, sync_repository)
          return unless sync_repository.bootstrap_canceled?
          return if sync_repository.provider_webhook_xid.blank? && project.import_data.nil?

          StopCleanupWorker.perform_async(sync_repository.id)
        end

        def log_released(project, sync_repository, previous_state)
          message = if previous_state == 'provisioning'
                      'Continuous sync was not enabled because the import did not finish'
                    else
                      'Continuous sync was stopped because the import did not finish'
                    end

          ::Gitlab::GithubImport::Logger.warn(
            Labkit::Fields::LOG_MESSAGE => message,
            Labkit::Fields::GL_PROJECT_ID => project.id,
            import_sync_repository_id: sync_repository.id,
            import_status: project.import_status,
            previous_authority_state: previous_state
          )
        end
      end
    end
  end
end
