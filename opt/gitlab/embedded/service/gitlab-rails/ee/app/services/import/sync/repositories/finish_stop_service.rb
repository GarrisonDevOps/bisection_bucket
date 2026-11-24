# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Runs the final provider checks and makes the GitLab project editable. After a failed or canceled import
      # there is nothing current to check, so it skips the final pass.
      #
      # The lease is held for the whole invocation; the row lock only around each check-and-write, never
      # across a provider call. Any failure keeps the project read-only (cutover_failed) and retryable.
      class FinishStopService
        include ::Gitlab::InternalEventsTracking

        IncompleteFinalCheckError = Class.new(StandardError)
        StaleStopError = Class.new(StandardError)
        ProviderRepositoryGoneError = Class.new(StandardError)

        def initialize(repository, application_generation:, now: -> { Time.current })
          @repository = repository
          @application_generation = application_generation
          @now = now
        end

        # Returns true only once GitLab holds the authority. A page that remains returns false and leaves the
        # row cutting_over. A lost or contended lease, or a rate limit, raises with the row unchanged; any other
        # error marks the stop cutover_failed and is re-raised. A 401 also counts toward disconnecting, so a
        # revoked token ends in the reconnect flow instead of retrying forever.
        def execute
          ApplicationLease.new(repository.id).execute do |lease_context|
            resume_failed_stop!(lease_context)
            verify_stop_fence!(lease_context)
            next complete_unfinished_import_stop!(lease_context) unless repository.project.import_finished?

            source_result = reconcile_source(lease_context)
            next false if source_result[:follow_up]

            lease_context.renew!
            next false if reconcile_lfs(lease_context, source_result[:lfs_revisions])[:follow_up]

            lease_context.renew!
            next false if reconcile_work_items(lease_context)[:follow_up]

            lease_context.renew!
            complete_stop!(lease_context, reason: 'final_pass')
          rescue ApplicationLease::LostLeaseError, ::Gitlab::GithubImport::RateLimitError
            raise
          rescue ProviderRepositoryGoneError => error
            log_provider_repository_gone(error.cause)
            complete_stop!(lease_context, reason: 'github_repository_gone', require_current_states: false)
          rescue StandardError => error
            repository.record_auth_failure! if error.is_a?(Octokit::Unauthorized)
            mark_failed(lease_context, error)
            raise
          end
        end

        private

        attr_reader :repository, :application_generation, :now

        # Reopens only the same fenced stop after a failure. A newer request or a completed stop is untouched.
        def resume_failed_stop!(lease_context)
          resumed = repository.with_lock do
            lease_context.verify_repository!(repository.id)
            next false unless repository.cutover_failed?
            next false unless repository.application_generation_current?(application_generation)

            repository.update!(authority_state: :cutting_over)
            true
          end

          return unless resumed

          ::Gitlab::GithubImport::Logger.info(**transition_payload(from: 'cutover_failed', to: 'cutting_over'))
        end

        def reconcile_source(lease_context)
          ReconcileSourceService.new(
            repository,
            application_generation: application_generation,
            allow_cutover: true,
            now: now
          ).execute(lease_context: lease_context)
        rescue Octokit::NotFound, Errors::ProviderIdentityError
          # No final pass can ever succeed, so GitLab takes over with what it already has.
          raise ProviderRepositoryGoneError, 'The GitHub repository is no longer available'
        end

        def reconcile_lfs(lease_context, lfs_revisions)
          ReconcileLfsService.new(
            repository,
            application_generation: application_generation,
            allow_cutover: true,
            now: now,
            lfs_revisions: lfs_revisions
          ).execute(lease_context: lease_context)
        end

        def reconcile_work_items(lease_context)
          ReconcileWorkItemsService.new(
            repository,
            application_generation: application_generation,
            allow_cutover: true,
            now: now
          ).execute(lease_context: lease_context)
        end

        def complete_stop!(lease_context, reason:, require_current_states: true)
          repository.with_lock do
            verify_stop_fence!(lease_context)
            validate_current_states!(locked_states) if require_current_states
            completed_at = now.call

            # Last check before the single irreversible write.
            lease_context.verify_repository!(repository.id)
            repository.update!(
              authority_state: :gitlab_canonical,
              application_generation: application_generation + 1,
              cutover_completed_at: completed_at
            )
          end

          ::Gitlab::GithubImport::Logger.info(**transition_payload(from: 'cutting_over', to: 'gitlab_canonical'))
          track_internal_event(
            'complete_import_continuous_sync_stop',
            project: repository.project,
            namespace: repository.project.namespace,
            additional_properties: { label: repository.project.import_type, property: reason }
          )
          true
        end

        def complete_unfinished_import_stop!(lease_context)
          complete_stop!(lease_context, reason: 'import_not_finished', require_current_states: false)

          ::Gitlab::GithubImport::Logger.info(
            message: 'stop completed without the final pass, the import did not finish',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            import_status: repository.project.import_status
          )
          true
        end

        def locked_states
          repository.sync_states_for_update(RepositoryState.domains.keys)
        end

        # A reconcile result with follow_up false does not prove a domain is current (it also means nothing
        # matched its fence), so "not lagging" is only trusted here, under the final lock.
        def validate_current_states!(states)
          return unless states.values.any?(&:lagging?)

          raise IncompleteFinalCheckError, 'The final GitHub update did not complete for every data type'
        end

        # Reloads the row under lock on every call; the in-memory instance may be stale.
        def verify_stop_fence!(lease_context)
          repository.with_lock do
            lease_context.verify_repository!(repository.id)
            next if repository.cutting_over? && repository.application_generation_current?(application_generation)

            raise StaleStopError, 'The GitHub stop request is no longer current'
          end
        end

        # A lost lease is swallowed here so the caller re-raises the pass error it is handling, not this one.
        def mark_failed(lease_context, error)
          failed = repository.with_lock do
            lease_context.verify_repository!(repository.id)
            next false unless repository.cutting_over?
            next false unless repository.application_generation_current?(application_generation)

            repository.update!(authority_state: :cutover_failed)
            true
          end

          return unless failed

          ::Gitlab::GithubImport::Logger.warn(
            **transition_payload(from: 'cutting_over', to: 'cutover_failed'),
            Labkit::Fields::ERROR_TYPE => error.class.name
          )
        rescue ApplicationLease::LostLeaseError
          nil
        end

        def log_provider_repository_gone(error)
          ::Gitlab::GithubImport::Logger.warn(
            message: 'GitHub repository unavailable, completing the stop without the final pass',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            Labkit::Fields::ERROR_TYPE => error.class.name
          )
        end

        def transition_payload(from:, to:)
          {
            message: 'import sync repository authority changed',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            from: from,
            to: to,
            application_generation: repository.application_generation
          }
        end
      end
    end
  end
end
