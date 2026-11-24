# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Coalesces requested provider generations for one synced repository.
      class ReconcileWorker
        include ApplicationWorker

        RATE_LIMIT_FALLBACK_DELAY = 15.minutes
        RATE_LIMIT_MIN_DELAY = 1.minute
        RAISE_PRIORITY = [
          Errors::MissingCredentialsError,
          ::Import::Github::RefreshOauthTokenService::BadRefreshTokenError,
          ::Gitlab::GithubImport::RateLimitError,
          Octokit::Unauthorized
        ].freeze

        data_consistency :sticky
        feature_category :importers
        worker_has_external_dependencies!
        idempotent!
        # Only until_executed honors reschedule_once: a same-args enqueue (including our own follow-up)
        # made while a job runs is dropped and re-run once after it finishes, not left to fail on the lease.
        deduplicate :until_executed, if_deduplicated: :reschedule_once
        concurrency_limit -> { Gitlab::CurrentSettings.import_jobs_concurrency_limit }

        sidekiq_options retry: 5, dead: false

        # Counted once per pass, after its retries, so a 401 that a retry clears never counts.
        sidekiq_retries_exhausted do |msg, error|
          record_auth_failure(msg['args'][0], error) if error.is_a?(Octokit::Unauthorized)
        end

        def self.record_auth_failure(repository_id, error)
          repository = Import::Sync::Repository.find_by_id(repository_id)
          return unless repository

          disconnected = repository.with_lock do
            next false unless repository.provider_canonical?

            repository.record_auth_failure!
            repository.disconnected?
          end

          log_disconnect(repository, error) if disconnected
        end

        def self.log_disconnect(repository, error)
          ::Gitlab::GithubImport::Logger.warn(
            Labkit::Fields::LOG_MESSAGE => 'GitHub credentials stopped working, sync repository disconnected',
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            Labkit::Fields::ERROR_TYPE => error.class.name,
            import_sync_repository_id: repository.id,
            disconnect_reason: repository.disconnect_reason
          )
        end

        def perform(repository_id, application_generation)
          repository = Import::Sync::Repository.find_by_id(repository_id)
          return unless repository
          return unless repository.application_generation_current?(application_generation)

          # The finish stage drains the same placeholder reference store and enqueues the first pass itself, so
          # only a finished import reconciles. A failed or canceled one is released by
          # ReleaseUnfinishedImportWorker, but a job queued before that must not update it.
          unless repository.project.import_finished?
            log_import_not_finished(repository)
            return
          end

          result = ApplicationLease.new(repository.id).execute do |lease_context|
            reconcile_under_lease(repository, application_generation, lease_context)
          end

          repository.clear_auth_failures!
          log_extra_metadata_on_done(:applied_domains, result[:applied_domains])
          log_extra_metadata_on_done(:follow_up, result[:follow_up])
          self.class.perform_async(repository.id, application_generation) if result[:follow_up]
        rescue ::Gitlab::GithubImport::RateLimitError => error
          reschedule_after_rate_limit(repository, application_generation, error)
        rescue Errors::MissingCredentialsError,
          ::Import::Github::RefreshOauthTokenService::BadRefreshTokenError => error
          disconnect_without_credentials(repository, error)
        end

        private

        # Only a reconnect restores missing or unrefreshable credentials, so retrying cannot help.
        def disconnect_without_credentials(repository, error)
          disconnected = repository.with_lock do
            next false unless repository.provider_canonical?

            repository.disconnect!(:token_revoked, restore_to: :provider_canonical)
          end

          return self.class.log_disconnect(repository, error) if disconnected

          ::Gitlab::GithubImport::Logger.warn(
            Labkit::Fields::LOG_MESSAGE => 'GitHub credentials missing, sync repository left as is',
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            import_sync_repository_id: repository.id,
            authority_state: repository.authority_state
          )
        end

        def log_import_not_finished(repository)
          ::Gitlab::GithubImport::Logger.info(
            message: 'skipping reconciliation, the import did not finish',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            import_status: repository.project.import_status
          )
        end

        # A rate limit resets on GitHub's clock, not Sidekiq's backoff, so reschedule for the reset instead of
        # spending retries. The floor stops a zero or negative reset from re-enqueueing in a tight loop.
        def reschedule_after_rate_limit(repository, application_generation, error)
          delay = [error.reset_in || rate_limit_resets_in(repository), RATE_LIMIT_MIN_DELAY].max

          ::Gitlab::GithubImport::Logger.info(
            message: 'GitHub rate limit reached, rescheduling reconciliation',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            reschedule_in_s: delay.to_i
          )
          self.class.perform_in(delay, repository.id, application_generation)
        end

        def rate_limit_resets_in(repository)
          Authentication.for(repository).client(parallel: true).rate_limit_resets_in
        rescue StandardError => error
          ::Gitlab::ErrorTracking.track_exception(error, import_sync_repository_id: repository.id)
          RATE_LIMIT_FALLBACK_DELAY
        end

        def reconcile_under_lease(repository, application_generation, lease_context)
          source_result = {}
          passes = [
            -> do
              source_result = ReconcileSourceService.new(repository, application_generation: application_generation)
                .execute(lease_context: lease_context)
            end,
            -> do
              ReconcileLfsService.new(
                repository,
                application_generation: application_generation,
                lfs_revisions: source_result[:lfs_revisions]
              ).execute(lease_context: lease_context)
            end,
            -> do
              ReconcileWorkItemsService.new(repository, application_generation: application_generation)
                .execute(lease_context: lease_context)
            end
          ]
          results = []
          failures = []

          passes.each do |pass|
            results << pass.call
          rescue ApplicationLease::LostLeaseError
            raise
          rescue ::Gitlab::GithubImport::RateLimitError => error
            failures << error
            break
          rescue StandardError => error
            failures << error
          end

          # Their health is independent, so every domain gets one attempt under the same lease, except after a
          # rate limit: they share one token. A lost lease aborts: no later mutation is safe.
          raise_failure(repository, failures) if failures.any?

          {
            applied_domains: results.flat_map { |result| result[:applied_domains] },
            follow_up: results.any? { |result| result[:follow_up] }
          }
        end

        # Raises one failure and tracks the rest. All domains share one token, so missing credentials (disconnect)
        # win, then a rate limit (reschedule instead of spending retries), then a 401 (counted once retries run out).
        def raise_failure(repository, failures)
          raised = RAISE_PRIORITY.filter_map { |klass| failures.detect { |error| error.is_a?(klass) } }.first ||
            failures.first

          failures.each do |error|
            next if error.equal?(raised)

            ::Gitlab::ErrorTracking.track_exception(error, import_sync_repository_id: repository.id)
          end

          raise raised
        end
      end
    end
  end
end
