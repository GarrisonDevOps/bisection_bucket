# frozen_string_literal: true

module AuthorizedProjectUpdate
  class ProjectRecalculateService
    # Service for refreshing all the authorizations to a particular project.
    include Gitlab::Utils::StrongMemoize

    def initialize(project)
      @project = project
    end

    def execute
      if shared_write_path?
        write_through_shared_path
      elsif needs_refresh?
        log_refresh(requested_changes, refresh_authorizations, shared_write_path: false)
      end

      ServiceResponse.success
    end

    private

    attr_reader :project

    # The shared path refuses to run inside a transaction, which some synchronous callers hold.
    def shared_write_path?
      !::ProjectAuthorization.inside_transaction? && Feature.enabled?(:authz_project_refresh_write_path, project)
    end

    def write_through_shared_path
      payload = Authz::ProjectAuthorizations::RecalculateProjectService.new(project.id).execute.payload

      log_refresh(payload[:requested], payload[:written], shared_write_path: true)
    end

    def requested_changes
      Authz::ProjectAuthorizations::WriteBatchService::Result.new(
        authorizations_to_create.size, user_ids_to_remove.size
      )
    end

    # Compared with the requested counts, the written ones show when a write differed from what the refresh found.
    # A per-user refresh on the shared path has no separate comparison, so it logs only what it wrote.
    def log_refresh(requested, written, shared_write_path:)
      counts = [written.rows_added, written.rows_deleted]
      counts += [requested.rows_added, requested.rows_deleted] if requested
      return if counts.all?(&:zero?)

      requested_counts = if requested
                           {
                             'project_refresh.requested_add_count': requested.rows_added,
                             'project_refresh.requested_remove_count': requested.rows_deleted
                           }
                         else
                           {}
                         end

      Gitlab::AppJsonLogger.info(
        event: 'project_authorizations_project_refresh',
        Labkit::Fields::GL_PROJECT_ID.to_sym => project.id,
        Labkit::Fields::GL_USER_ID.to_sym => logged_user_id,
        'project_refresh.service': self.class.name,
        **requested_counts,
        'project_refresh.rows_added_count': written.rows_added,
        'project_refresh.rows_deleted_count': written.rows_deleted,
        'project_refresh.shared_write_path': shared_write_path
      )
    end

    def logged_user_id
      nil
    end

    def needs_refresh?
      user_ids_to_remove.any? ||
        authorizations_to_create.any?
    end

    # Read from the primary, where the diff is applied. Replicas cannot skip dead index
    # entries, so a read soon after a large removal can exceed the statement timeout.
    # @return [Array<Array(Integer, Integer)>] `[user_id, access_level]` pairs the diff compares
    def current_authorizations
      strong_memoize(:current_authorizations) do
        ::Gitlab::Database::LoadBalancing::SessionMap.current(ProjectAuthorization.load_balancer).use_primary do
          apply_scopes(project.project_authorizations)
            .pluck(:user_id, :access_level) # rubocop: disable CodeReuse/ActiveRecord -- reads only the two columns the diff needs
        end
      end
    end

    def fresh_authorizations
      effective_access_levels
    end
    strong_memoize_attr :fresh_authorizations

    def user_ids_to_remove
      strong_memoize(:user_ids_to_remove) do
        stale_authorizations
          .map { |user_id, _| user_id }
          .reject { |user_id| skipped_user_ids.include?(user_id) }
      end
    end

    def authorizations_to_create
      strong_memoize(:authorizations_to_create) do
        missing_authorizations.filter_map do |user_id, access_level|
          next if skipped_user_ids.include?(user_id)

          {
            user_id: user_id,
            access_level: access_level,
            project_id: project.id
          }
        end
      end
    end

    def stale_authorizations
      current_authorizations - fresh_authorizations
    end
    strong_memoize_attr :stale_authorizations

    def missing_authorizations
      fresh_authorizations - current_authorizations
    end
    strong_memoize_attr :missing_authorizations

    # Blocked users keep their rows until they are active again. Only users whose rows would
    # change are looked up, so projects with many authorized users don't load all of them.
    def skipped_user_ids
      changed_user_ids = (stale_authorizations + missing_authorizations).map { |user_id, _| user_id }

      Authz::ProjectAuthorizations::BlockedUserRefreshSkip
        .skipped_user_ids(changed_user_ids, skipped_in: :project_recalculate)
    end
    strong_memoize_attr :skipped_user_ids

    def refresh_authorizations
      ProjectAuthorizations::Changes.new do |changes|
        changes.add(authorizations_to_create)
        changes.remove_users_in_project(project, user_ids_to_remove)
      end.apply!
    end

    def apply_scopes(project_authorizations)
      project_authorizations
    end

    def effective_access_levels
      Projects::Members::EffectiveAccessLevelFinder.new(project).execute
    end
  end
end

AuthorizedProjectUpdate::ProjectRecalculateService.prepend_mod
