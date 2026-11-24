# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Runs the final provider check of a stop for the generation it was requested with, and hands the
      # post-cutover cleanup to StopCleanupWorker once the cutover has committed.
      class FinishStopWorker
        include ApplicationWorker

        data_consistency :sticky
        feature_category :importers
        worker_has_external_dependencies!
        idempotent!
        # Only until_executed honors reschedule_once: our own follow-up (same args) enqueued while a job runs is
        # re-run once after it finishes, instead of failing on the lease.
        deduplicate :until_executed, if_deduplicated: :reschedule_once
        concurrency_limit -> { Gitlab::CurrentSettings.import_jobs_concurrency_limit }

        sidekiq_options retry: 5, dead: false

        def perform(repository_id, application_generation)
          repository = Import::Sync::Repository.find_by_id(repository_id)
          return unless repository

          # The completion write sets exactly generation + 1: this stop already finished, and a retry must still
          # recover a cleanup enqueue that was lost after the commit.
          if repository.gitlab_canonical? && repository.application_generation_current?(application_generation + 1)
            StopCleanupWorker.perform_async(repository.id)
            return
          end

          return unless repository.cutting_over? || repository.cutover_failed?
          return unless repository.application_generation_current?(application_generation)

          if FinishStopService.new(repository, application_generation: application_generation).execute
            StopCleanupWorker.perform_async(repository.id)
          else
            self.class.perform_async(repository.id, application_generation)
          end
        rescue FinishStopService::StaleStopError
          # A newer request or a finished stop owns the row; retrying can never succeed.
          nil
        rescue ::Gitlab::GithubImport::RateLimitError => error
          reschedule_after_rate_limit(repository, application_generation, error)
        end

        private

        def reschedule_after_rate_limit(repository, application_generation, error)
          delay = [
            error.reset_in || ReconcileWorker::RATE_LIMIT_FALLBACK_DELAY,
            ReconcileWorker::RATE_LIMIT_MIN_DELAY
          ].max

          ::Gitlab::GithubImport::Logger.info(
            message: 'GitHub rate limit reached, rescheduling the stop',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            reschedule_in_s: delay.to_i
          )
          self.class.perform_in(delay, repository.id, application_generation)
        end
      end
    end
  end
end
