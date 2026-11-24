# frozen_string_literal: true

module AuthorizedProjectUpdate
  # Service for finding the authorized_projects records of a user that needs addition or removal.
  #
  # Usage:
  #
  #     user = User.find_by(username: 'alice')
  #     service = AuthorizedProjectUpdate::FindRecordsDueForRefreshService.new(some_user)
  #     service.execute
  class FindRecordsDueForRefreshService
    # A new project's members get access from its own ProjectRecalculateWorker job,
    # which usually runs within a minute or two of creation.
    RECENTLY_CREATED_PROJECT_WINDOW = 10.minutes
    PROJECT_LOOKUP_BATCH_SIZE = 1_000

    # Archived projects where the user's project_authorizations row is missing or below the
    # access level their memberships give them. Filled by #execute when `archived_grants` is given,
    # nil otherwise so logs can tell "not measured" apart from "none found".
    #
    # @return [Array<Integer>, nil]
    attr_reader :archived_grant_project_ids

    # @param archived_grants [Symbol, nil] :report lists the grants on archived projects in
    #   {#archived_grant_project_ids}, a grant being a missing row or one below the access level
    #   the user's memberships give. The result is the same either way.
    # @param read_current_from_primary [Boolean] reads the stored rows from the primary, so they include
    #   writes a caller has just waited for even when it hasn't stuck to the primary
    def initialize(
      user, source: nil, incorrect_auth_found_callback: nil, missing_auth_found_callback: nil,
      skip_projects_pending_refresh: false, skip_deleted_projects: false, archived_grants: nil,
      read_current_from_primary: false)
      @user = user
      @source = source
      @incorrect_auth_found_callback = incorrect_auth_found_callback
      @missing_auth_found_callback = missing_auth_found_callback
      @skip_projects_pending_refresh = skip_projects_pending_refresh
      @skip_deleted_projects = skip_deleted_projects
      @archived_grants = archived_grants
      @read_current_from_primary = read_current_from_primary
    end

    def execute
      current = current_authorizations_per_project
      fresh = fresh_access_levels_per_project

      skipped = project_ids_pending_own_refresh(current, fresh) | deleted_project_ids(current, fresh)
      current.except!(*skipped)
      fresh.except!(*skipped)

      @archived_grant_project_ids = find_archived_grant_project_ids(current, fresh)

      # Projects that have more than one authorizations associated with
      # the user needs to be deleted.
      # The correct authorization is added to the ``add`` array in the
      # next stage.
      remove = projects_with_duplicates - skipped
      current.except!(*projects_with_duplicates)

      remove |= current.each_with_object([]) do |(project_id, access_level), array|
        next if fresh[project_id] && fresh[project_id] == access_level

        # rows not in the new list or with a different access level should be
        # removed.

        if incorrect_auth_found_callback
          incorrect_auth_found_callback.call(project_id, access_level)
        end

        array << project_id
      end

      add = fresh.each_with_object([]) do |(project_id, level), array|
        next if current[project_id] && current[project_id] == level

        # rows not in the old list or with a different access level should be
        # added.

        if missing_auth_found_callback
          missing_auth_found_callback.call(project_id, level)
        end

        array << {
          user_id: user.id,
          project_id: project_id,
          access_level: level
        }
      end

      [remove, add]
    end

    def needs_refresh?
      remove, add = execute

      remove.present? || add.present?
    end

    # Both sides of the diff are read as raw [project_id, access_level] pairs
    # rather than ActiveRecord objects. See ProjectAuthorization for why.
    def fresh_access_levels_per_project
      ProjectAuthorization.access_levels_by_project(fresh_authorizations)
    end

    def current_authorizations_per_project
      current_authorizations.to_h
    end

    def current_authorizations
      # Read off the model rather than through `user.project_authorizations`:
      # `pluck` short-circuits to an association's in-memory target when it is
      # already loaded, which would silently return stale rows here.
      @current_authorizations ||= if read_current_from_primary
                                    # Without write_fallback, a write earlier in the job would make the
                                    # session stick to the primary once the block ends.
                                    ::Gitlab::Database::LoadBalancing::SessionMap
                                      .current(ProjectAuthorization.load_balancer)
                                      .use_primary(write_fallback: false) { read_current_authorizations }
                                  else
                                    read_current_authorizations
                                  end
    end

    def fresh_authorizations
      Gitlab::ProjectAuthorizations.new(user).calculate
    end

    private

    attr_reader :user, :source, :incorrect_auth_found_callback, :missing_auth_found_callback,
      :skip_projects_pending_refresh, :skip_deleted_projects, :archived_grants, :read_current_from_primary

    def read_current_authorizations
      ProjectAuthorization.project_ids_and_access_levels_for(user.id)
    end

    # Safety-net refreshes leave out projects whose own refresh job may not have run yet,
    # so they don't count (or race) access that job is about to write.
    def project_ids_pending_own_refresh(current, fresh)
      return [] unless skip_projects_pending_refresh

      changed = (current.keys | fresh.keys).reject { |id| current[id] == fresh[id] } | projects_with_duplicates

      since = RECENTLY_CREATED_PROJECT_WINDOW.ago

      changed.each_slice(PROJECT_LOOKUP_BATCH_SIZE).flat_map do |ids|
        ProjectAuthorization.project_ids_pending_own_refresh(ids, since: since)
      end
    end

    # Safety-net refreshes also leave out rows whose project has been deleted. Loose-foreign-key
    # cleanup removes those rows, but it can trail a mass deletion by hours, and deleting them
    # here would count that lag as access the primary refresh path had missed.
    def deleted_project_ids(current, fresh)
      return [] unless skip_deleted_projects

      # The fresh set joins `projects`, so a deleted project can only be on the current side
      candidates = current.keys - fresh.keys

      candidates.each_slice(PROJECT_LOOKUP_BATCH_SIZE).flat_map do |ids|
        ProjectAuthorization.deleted_project_ids(ids)
      end
    end

    # Archived projects where the user would get access or a higher access level. Counted to size
    # how much of what refreshes write could wait: archived projects are read-only, so a missing or
    # lower row there only shows in lists and search.
    def find_archived_grant_project_ids(current, fresh)
      return unless archived_grants == :report

      granted = fresh.filter_map do |project_id, level|
        project_id if current[project_id].nil? || level > current[project_id]
      end

      # Duplicate rows are removed and re-added whatever the access level, so they are cleanup
      # rather than a grant.
      (granted - projects_with_duplicates).each_slice(PROJECT_LOOKUP_BATCH_SIZE).flat_map do |ids|
        ProjectAuthorization.archived_project_ids(ids)
      end
    end

    def projects_with_duplicates
      @projects_with_duplicates ||= current_authorizations
                                      .group_by(&:first)
                                      .select { |_project_id, authorizations| authorizations.count > 1 }
                                      .keys
    end
  end
end
