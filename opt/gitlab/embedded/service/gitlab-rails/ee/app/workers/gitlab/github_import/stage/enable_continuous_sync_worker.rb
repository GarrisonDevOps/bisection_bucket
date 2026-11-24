# frozen_string_literal: true

module Gitlab
  module GithubImport
    module Stage
      class EnableContinuousSyncWorker # rubocop:disable Scalability/IdempotentWorker -- every run enqueues FinishImportWorker
        include ApplicationWorker

        data_consistency :sticky

        include StageMethods

        # Safe to resume: StartCatchUpService only flips from provisioning, so a retry after the flip changes nothing.
        resumes_work_when_interrupted!

        # Replaces the StageMethods block: a failure here must not fail an import whose data is already copied.
        sidekiq_retries_exhausted do |msg, e|
          finish_without_continuous_sync(msg['args'][0], e)
        end

        def self.finish_without_continuous_sync(project_id, exception)
          track_failure(project_id, exception)
          cancel_provisioning_sync_repository(project_id)

          FinishImportWorker.perform_async(project_id)
        end

        # Never raises, so a failure here (for example a deleted project) cannot keep the import from finishing.
        def self.track_failure(project_id, exception)
          Gitlab::Import::ImportFailureService.track(
            project_id: project_id,
            exception: exception,
            error_source: name,
            fail_import: false
          )
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, project_id: project_id, error_source: name)
        end
        private_class_method :track_failure

        def self.cancel_provisioning_sync_repository(project_id)
          sync_repository = Project.find_by_id(project_id)&.import_sync_repository

          ::Import::Sync::Repositories::CancelBootstrapService.new(sync_repository).execute
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, project_id: project_id, error_source: name)
        end
        private_class_method :cancel_provisioning_sync_repository

        def import(client, project)
          sync_repository = project.import_sync_repository

          if sync_repository.nil?
            info(project.id, message: 'no sync repository found, finishing without continuous sync')
          elsif start_catch_up(project, sync_repository)
            enable_webhook(client, project, sync_repository)
          end

          # There are no waiters, so the finish stage is enqueued directly rather than via AdvanceStageWorker.
          FinishImportWorker.perform_async(project.id)
        end

        private

        def start_catch_up(project, sync_repository)
          return true if ::Import::Sync::Repositories::StartCatchUpService.new(sync_repository).execute

          info(
            project.id,
            message: "sync repository is #{sync_repository.authority_state}, finishing without continuous sync"
          )
          false
        end

        def enable_webhook(client, project, sync_repository)
          ::Import::Sync::Github::Oauth::WebhookManagementService
            .new(sync_repository, client: client, callback_url: sync_repository.webhook_callback_url)
            .enable
        rescue ::Octokit::Unauthorized
          disconnect(project, sync_repository, :token_revoked)
        rescue ::Octokit::Forbidden => e
          raise unless e.instance_of?(::Octokit::Forbidden)

          disconnect(project, sync_repository, :insufficient_scope)
        end

        def disconnect(project, sync_repository, reason)
          sync_repository.with_lock do
            next unless sync_repository.provider_canonical?

            sync_repository.disconnect!(reason, restore_to: :provider_canonical)
          end

          info(
            project.id,
            message: 'could not create GitHub webhook, sync repository disconnected',
            disconnect_reason: reason.to_s
          )
        end
      end
    end
  end
end
