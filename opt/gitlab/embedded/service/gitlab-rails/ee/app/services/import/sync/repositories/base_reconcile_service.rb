# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Shared lease handling, application fence and failure recording for the per-domain reconcile services.
      class BaseReconcileService
        RATE_LIMIT_CODE = 'github_rate_limited'
        RATE_LIMIT_MESSAGE = 'GitHub rate limit reached'

        def initialize(repository, application_generation:, allow_cutover: false, now: -> { Time.current })
          @repository = repository
          @project = repository.project
          @application_generation = application_generation
          @allow_cutover = allow_cutover
          @now = now
        end

        def execute(lease_context: nil)
          if lease_context
            lease_context.verify_repository!(repository.id)
            return execute_with_failure_recording(lease_context)
          end

          ApplicationLease.new(repository.id).execute { |context| execute_with_failure_recording(context) }
        end

        private

        attr_reader :repository, :project, :application_generation, :allow_cutover, :now

        def reconcile_under_lease(_lease_context)
          raise NotImplementedError
        end

        def record_failure!(_error)
          raise NotImplementedError
        end

        def execute_with_failure_recording(lease_context)
          reconcile_under_lease(lease_context)
        rescue ApplicationLease::LostLeaseError
          raise
        rescue StandardError => error
          record_failure(error)
          raise
        end

        def record_failure(error)
          record_failure!(error)
        rescue StandardError => recording_error
          # The original pass error must be what propagates.
          ::Gitlab::ErrorTracking.track_exception(recording_error, import_sync_repository_id: repository.id)
        end

        def verify_application_fence!(lease_context)
          lease_context.verify!

          repository.with_lock do
            next if application_current?

            raise Errors::StaleApplicationError, 'Import sync repository application generation changed'
          end
        end

        def application_current?
          provider_application_allowed? && repository.application_generation_current?(application_generation)
        end

        def provider_application_allowed?
          repository.provider_canonical? || (allow_cutover && repository.cutting_over?)
        end

        # Health fields only get fixed messages; cursor contents and provider error details must never reach them.
        def mark_failed!(state, error)
          state.assign_attributes(failure_health(error))
          state.save!

          # The worker logs the reschedule.
          return if state.delayed?

          ::Gitlab::GithubImport::Logger.warn(
            message: self.class::FAILURE_LOG_MESSAGE,
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => project.id,
            Labkit::Fields::ERROR_TYPE => error.class.name,
            domain: state.domain,
            last_error_code: state.last_error_code,
            health_state: state.state
          )

          ::Gitlab::Metrics.counter(
            :gitlab_import_sync_reconcile_failures_total,
            'Number of failed GitHub continuous sync reconcile passes'
          ).increment(domain: state.domain, health_state: state.state)
        end

        # A rate limit is a wait on GitHub's clock that the worker reschedules, not a failure.
        def failure_health(error)
          state, code, message =
            if !provider_application_allowed?
              [:paused, 'github_updates_inactive', 'GitHub updates are not active']
            elsif error.is_a?(::Gitlab::GithubImport::RateLimitError)
              [:delayed, RATE_LIMIT_CODE, RATE_LIMIT_MESSAGE]
            else
              [:degraded, self.class::FAILURE_CODE, self.class::FAILURE_MESSAGE]
            end

          { state: state, last_error_code: code, last_error_message: message }
        end

        def request_lfs_pass
          repository.with_lock do
            state = repository.sync_states_for_update([ReconcileLfsService::DOMAIN]).fetch(ReconcileLfsService::DOMAIN)
            state.desired_generation += 1
            state.state = :pending unless state.running? || state.paused? || state.disconnected?
            state.save!
            state.desired_generation
          end
        end

        def authentication
          @authentication ||= Authentication.for(repository)
        end

        def provider_client
          @provider_client ||= authentication.client(parallel: true)
        end

        def result(applied_domains, follow_up)
          { applied_domains: applied_domains, follow_up: follow_up }
        end
      end
    end
  end
end
