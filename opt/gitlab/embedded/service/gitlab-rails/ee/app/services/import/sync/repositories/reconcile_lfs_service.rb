# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Updates the "lfs" domain: the LFS objects the repository's refs point to. The source pass asks for it when a
      # fetch changes refs. Each pass downloads one page; while pages remain, only this domain stays lagging.
      class ReconcileLfsService < BaseReconcileService
        DOMAIN = 'lfs'
        FAILURE_CODE = 'github_lfs_update_failed'
        FAILURE_MESSAGE = 'GitHub LFS update failed'
        FAILURE_LOG_MESSAGE = 'GitHub LFS reconciliation failed'

        def initialize(repository, lfs_revisions: nil, **options)
          super(repository, **options)
          @lfs_revisions = lfs_revisions
        end

        private

        attr_reader :lfs_revisions

        def reconcile_under_lease(lease_context)
          target = prepare_target
          return result([], false) unless target

          verify_application_fence!(lease_context)
          return result([], true) unless lfs_objects_complete?(lease_context, target[:revisions])

          apply_success(target[:generation], lease_context)
        end

        def prepare_target
          repository.with_lock do
            next unless application_current?

            state = locked_state
            next unless state.lagging?

            state.update!(state: :running, last_sync_started_at: now.call)
            { generation: state.desired_generation, revisions: revisions_to_scan(state) }
          end
        end

        def revisions_to_scan(state)
          return unless lfs_revisions
          return unless lfs_revisions[:generation] == state.desired_generation
          return unless state.synced_generation == state.desired_generation - 1

          lfs_revisions[:revisions]
        end

        def lfs_objects_complete?(lease_context, revisions)
          ReconcileLfsObjectsService.new(
            project,
            authentication: authentication,
            lease_context: lease_context,
            revisions: revisions
          ).execute
        rescue Errors::LfsReconciliationError
          raise unless allow_cutover

          ::Gitlab::GithubImport::Logger.warn(
            message: 'GitHub LFS update failed, finishing the stop without the missing LFS objects',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => project.id
          )
          true
        end

        def apply_success(target_generation, lease_context)
          lease_context.verify!

          repository.with_lock do
            unless application_current?
              raise Errors::StaleApplicationError, 'GitHub updates changed while LFS objects were being applied'
            end

            state = locked_state
            state.synced_generation = [state.synced_generation, target_generation].max
            state.state = state.lagging? ? :pending : :current
            state.last_successful_sync_at = now.call
            state.last_error_code = nil
            state.last_error_message = nil
            state.save!

            result([DOMAIN], state.lagging?)
          end
        end

        def record_failure!(error)
          repository.with_lock do
            state = locked_state
            mark_failed!(state, error) if state.running?
          end
        end

        def locked_state
          repository.sync_states_for_update([DOMAIN]).fetch(DOMAIN)
        end
      end
    end
  end
end
