# frozen_string_literal: true

module Users
  # Service for refreshing the authorized projects of a user.
  #
  # This particular service class can not be used to update data for the same
  # user concurrently. Doing so could lead to an incorrect state. To ensure this
  # doesn't happen a caller must synchronize access (e.g. using
  # `Gitlab::ExclusiveLease`).
  #
  # Usage:
  #
  #     user = User.find_by(username: 'alice')
  #     service = Users::RefreshAuthorizedProjectsService.new(some_user)
  #     service.execute
  class RefreshAuthorizedProjectsService
    include Gitlab::Utils::StrongMemoize

    attr_reader :user, :source

    # user - The User for which to refresh the authorized projects.
    def initialize(user, source: nil, incorrect_auth_found_callback: nil, missing_auth_found_callback: nil)
      @user = user
      @source = source
      @incorrect_auth_found_callback = incorrect_auth_found_callback
      @missing_auth_found_callback = missing_auth_found_callback
    end

    # This method returns the updated User object.
    def execute
      # We need an up to date User object that has access to all relations that
      # may have been created earlier.
      user.reset

      return user if Authz::ProjectAuthorizations::BlockedUserRefreshSkip.skip_and_log?(user, skipped_in: :user_refresh)

      wait_for_writers if shared_path?

      @finder = AuthorizedProjectUpdate::FindRecordsDueForRefreshService.new(
        user,
        source: source,
        incorrect_auth_found_callback: incorrect_auth_found_callback,
        missing_auth_found_callback: missing_auth_found_callback,
        skip_projects_pending_refresh: safety_net_refresh?,
        skip_deleted_projects: safety_net_refresh?,
        archived_grants: (:report if Feature.enabled?(:log_archived_project_authorization_grants, user)),
        read_current_from_primary: shared_path?
      )
      remove, add = finder.execute

      # Most refreshes find nothing to change. Skipping `update_authorizations`
      # for those avoids a per-refresh log document that carries no information;
      # the refresh workers' Sidekiq job metrics still show volume and duration.
      return user if remove.blank? && add.blank?

      update_authorizations(remove, add)
    end

    private

    attr_reader :incorrect_auth_found_callback, :missing_auth_found_callback, :finder

    # Updates the list of authorizations for the current user.
    #
    # remove - The project IDs of the authorization rows to remove.
    # add - Rows to insert in the form `[{ user_id: user_id, project_id: project_id, access_level: access_level}, ...]`
    def update_authorizations(remove, add)
      authorization_changes = if shared_path?
                                write_through_shared_path(remove, add)
                              else
                                ProjectAuthorizations::Changes.new do |changes|
                                  changes.add(add)
                                  changes.remove_projects_for_user(user, remove)
                                end.apply!
                              end

      user.update!(project_authorizations_recalculated_at: Time.zone.now)

      log_refresh_details(authorization_changes, remove, add)

      # Since we batch insert authorization rows, Rails' associations may get
      # out of sync. As such we force a reload of the User object.
      user.reset
    end

    # Checked once, so the wait and the write always take the same path.
    def shared_path?
      Feature.enabled?(:authz_refresh_write_path, user)
    end
    strong_memoize_attr :shared_path?

    # Runs before the comparison reads stored rows; otherwise a writer still holding the lock could commit an
    # older result after it. The wait's transaction counts as a write, so it mustn't stick the calculation to the
    # primary; the finder reads just the stored rows from there instead.
    def wait_for_writers
      ::Gitlab::Database::LoadBalancing::SessionMap.current(ProjectAuthorization.load_balancer).without_sticky_writes do
        Authz::ProjectAuthorizations::WriteBatchService.wait_for_user_writers(user.id)
      end
    end

    # Rechecks the changed projects under the user's lock and writes them there, so this refresh can't
    # overwrite a newer result from another writer on the shared path.
    def write_through_shared_path(remove, add)
      project_ids = remove | add.map { |row| row.fetch(:project_id) }

      Authz::ProjectAuthorizations::RecalculateUserService.new(user.id, project_ids: project_ids)
        .execute.payload[:written]
    end

    def log_refresh_details(changes, remove, add)
      record_safety_net_refresh_metrics(changes)

      Gitlab::AppJsonLogger.info(
        event: 'authorized_projects_refresh',
        user_id: user.id,
        'authorized_projects_refresh.source': source,
        # `source` is always the class of the worker that ended up running this
        # service, which for the safety-net workers is the same regardless of why
        # they were triggered. `trigger` instead carries the originally
        # enqueuing caller (see `related_class` propagation in
        # `UserProjectAccessChangedService`/`UserRefreshOverUserRangeWorker`)
        'authorized_projects_refresh.trigger': refresh_trigger,
        'authorized_projects_refresh.rows_deleted_count': changes.rows_deleted,
        'authorized_projects_refresh.rows_added_count': changes.rows_added,
        'authorized_projects_refresh.archived_grants_count': finder.archived_grant_project_ids&.size,
        # Compared with the counts above, these show when a write differed from what the refresh found.
        'authorized_projects_refresh.requested_remove_count': remove.size,
        'authorized_projects_refresh.requested_add_count': add.size,
        'authorized_projects_refresh.shared_write_path': shared_path?,
        # most often there's only a few entries in remove and add, but limit it to the first 5
        # entries to avoid flooding the logs
        'authorized_projects_refresh.rows_deleted_slice': remove.first(5),
        # Logged arrays should have uniformly typed values.
        'authorized_projects_refresh.rows_added_slice':
          add.first(5).map { |row| row.values_at(:user_id, :project_id, :access_level) }
      )
    end

    def refresh_trigger
      Gitlab::ApplicationContext.current_context_attribute('meta.related_class').presence
    end

    def safety_net_refresh?
      Gitlab::ApplicationContext.current_context_attribute(
        'meta.authorized_projects_refresh_purpose'
      ) == UserProjectAccessChangedService::SAFETY_NET_REFRESH_PURPOSE
    end

    def record_safety_net_refresh_metrics(changes)
      return unless safety_net_refresh?

      labels = { trigger: refresh_trigger.to_s }

      counter = Gitlab::Metrics.counter(
        :gitlab_authorized_projects_safety_net_refresh_rows_total,
        'Total number of project_authorizations rows added or deleted by a safety-net refresh'
      )

      counter.increment(labels.merge(direction: 'deleted'), changes.rows_deleted) if changes.rows_deleted > 0
      counter.increment(labels.merge(direction: 'added'), changes.rows_added) if changes.rows_added > 0
    end
  end
end
