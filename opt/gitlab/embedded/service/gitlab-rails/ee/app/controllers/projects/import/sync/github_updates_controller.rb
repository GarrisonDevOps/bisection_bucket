# frozen_string_literal: true

module Projects
  module Import
    module Sync
      # Shows and controls the GitHub updates of a project imported with continuous sync, from repository settings.
      class GithubUpdatesController < Projects::ApplicationController
        POLLING_INTERVAL = 5_000
        STOP_POLLING = -1

        before_action :authorize_read_github_update!, only: :status
        before_action :authorize_update_github_update!, only: :update_now
        before_action :authorize_stop_github_update!, only: :stop
        before_action :ensure_github_updates_available

        feature_category :importers

        def status
          Gitlab::PollingInterval.set_header(
            response, interval: import_sync_repository.gitlab_canonical? ? STOP_POLLING : POLLING_INTERVAL
          )

          render json: status_payload
        end

        def update_now
          ::Import::Sync::Repositories::RequestUpdateService.new(import_sync_repository).execute

          message = s_('GithubUpdatesSettings|Update scheduled.')

          render json: status_payload.merge(message: message), status: :accepted
        rescue ::Import::Sync::Errors::InactiveAuthorityError
          render json: {
            error: 'github_updates_not_updatable',
            message: s_(
              # rubocop:disable Layout/LineLength -- Keep the localized sentence extractable as one literal.
              'GithubUpdatesSettings|An update can only be requested while GitHub updates are on and not being stopped. Refresh the page to see the current status.'
              # rubocop:enable Layout/LineLength
            )
          }, status: :unprocessable_entity
        end

        def stop
          ::Import::Sync::Repositories::RequestStopService
            .new(import_sync_repository, current_user: current_user)
            .execute

          render json: status_payload, status: :accepted
        rescue ::Import::Sync::Repositories::RequestStopService::ConnectionLostError
          render json: {
            error: 'github_connection_lost',
            message: s_(
              # rubocop:disable Layout/LineLength -- Keep the localized sentence extractable as one literal.
              'GithubUpdatesSettings|GitLab must check GitHub for the latest changes before this project can be made editable.'
              # rubocop:enable Layout/LineLength
            )
          }, status: :unprocessable_entity
        rescue ::Import::Sync::Repositories::RequestStopService::InvalidStateError
          render json: {
            error: 'github_updates_not_stoppable',
            message: not_stoppable_message
          }, status: :unprocessable_entity
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError,
          ::Import::Sync::Repositories::ApplicationLease::LostLeaseError
          render json: {
            error: 'github_updates_busy',
            message: s_('GithubUpdatesSettings|GitHub updates are still finishing. Try stopping updates again.')
          }, status: :conflict
        end

        private

        def import_sync_repository
          @import_sync_repository ||= project.import_sync_repository
        end

        # Not gated on github_continuous_import: a row created while it was on must stay stoppable after a rollback,
        # because WritePolicy keeps the project read-only until it's stopped.
        def ensure_github_updates_available
          render_404 unless import_sync_repository
        end

        def status_payload
          ::Import::Sync::GithubUpdatesStatusPresenter.new(import_sync_repository).to_h
        end

        def not_stoppable_message
          if project.import_in_progress?
            s_('GithubUpdatesSettings|Wait for the import to finish, then stop GitHub updates.')
          else
            s_('GithubUpdatesSettings|GitHub updates cannot be stopped right now. Refresh the page and try again.')
          end
        end
      end
    end
  end
end
