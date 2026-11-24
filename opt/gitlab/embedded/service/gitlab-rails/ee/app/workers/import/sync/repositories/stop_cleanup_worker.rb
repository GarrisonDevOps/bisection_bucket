# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Removes what a finished stop, or the release of an unfinished import, leaves behind: the GitHub webhook,
      # then the stored OAuth token. It runs after the row left GitHub's authority, so nothing here can undo that.
      class StopCleanupWorker
        include ApplicationWorker

        data_consistency :sticky
        feature_category :importers
        worker_has_external_dependencies!
        idempotent!
        # A re-run adds nothing, so a duplicate enqueued while a run is in progress can simply be dropped.
        deduplicate :until_executed
        concurrency_limit -> { Gitlab::CurrentSettings.import_jobs_concurrency_limit }

        sidekiq_options retry: 5, dead: false

        # A GitHub 5xx or rate limit keeps the token through the retries so the hook can still be deleted. After
        # that the local hook record is cleared, so leftover deliveries are rejected, and the token is removed.
        sidekiq_retries_exhausted do |job, error|
          repository = Import::Sync::Repository.find_by_id(job['args'].first)
          ::Gitlab::ErrorTracking.track_exception(error, import_sync_repository_id: job['args'].first)
          next unless released?(repository)

          repository.update!(provider_webhook_xid: nil, webhook_secret: nil)
          remove_import_data(repository)
        end

        def self.released?(repository)
          !!(repository&.gitlab_canonical? || repository&.bootstrap_canceled?)
        end

        # Freshly loaded: a project loaded earlier can still cache a retaining sync state, which makes
        # remove_import_data a silent no-op.
        def self.remove_import_data(repository)
          Project.find_by_id(repository.project_id)&.remove_import_data
        end

        def perform(repository_id)
          repository = Import::Sync::Repository.find_by_id(repository_id)
          return unless self.class.released?(repository)

          delete_webhook(repository)
          self.class.remove_import_data(repository)

          ::Gitlab::GithubImport::Logger.info(
            message: 'import sync cleanup after stop finished',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id
          )
        end

        private

        # A 401 or 404 clears the record inside disable; other errors raise so Sidekiq retries the deletion.
        def delete_webhook(repository)
          return if repository.provider_webhook_xid.blank?

          begin
            client = Authentication.for(repository).client(parallel: true)
          rescue Errors::MissingCredentialsError
            # No token can ever delete the hook, so retrying is useless; clearing the record rejects its deliveries.
            return repository.update!(provider_webhook_xid: nil, webhook_secret: nil)
          end

          Import::Sync::Github::Oauth::WebhookManagementService
            .new(repository, client: client, callback_url: nil)
            .disable
        end
      end
    end
  end
end
