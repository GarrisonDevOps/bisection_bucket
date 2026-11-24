# frozen_string_literal: true

module Preloaders
  # This class preloads the max access level (role) for the user within the given projects and
  # stores the values in requests store via the ProjectTeam class.
  class UserMaxAccessLevelInProjectsPreloader
    def initialize(projects, user)
      # Kept so lookups from memberships can use projects and IDs already cached for the request.
      @project_list = projects if projects.is_a?(Array)
      @projects = if projects.is_a?(Array)
                    Project.id_in(projects)
                  else
                    # Push projects base query in to a sub-select to avoid
                    # table name clashes. Performs better than aliasing.
                    Project.id_in(projects.subquery(:id))
                  end

      @user = user
    end

    def execute
      return unless @user

      Gitlab::Instrumentation::Authz.measure do
        next preload_from_memberships if Authz::UserProjectGrants.enabled_for?(@user.id)

        preload_from_project_authorizations
      end
    end

    private

    # The request cache key only needs the project's class and ID, so the full record isn't loaded.
    def preload_from_memberships
      levels = Authz::UserProjectGrants.new(@user.id).max_access_levels(@project_list || @projects)

      levels.each do |project_id, access_level|
        ProjectTeam.new(Project.instantiate('id' => project_id)).write_member_access_for_user_id(@user.id, access_level)
      end
    end

    def preload_from_project_authorizations
      project_authorizations = ProjectAuthorization.arel_table

      auths = @projects
                .select(
                  Project.default_select_columns,
                  project_authorizations[:user_id],
                  project_authorizations[:access_level]
                )
                .joins(project_auth_join)

      auths.each do |project|
        access_level = project.access_level || Gitlab::Access::NO_ACCESS
        ProjectTeam.new(project).write_member_access_for_user_id(@user.id, access_level)
      end
    end

    def project_auth_join
      project_authorizations = ProjectAuthorization.arel_table
      projects = Project.arel_table

      projects
        .join(
          project_authorizations.as(project_authorizations.name),
          Arel::Nodes::OuterJoin
        )
        .on(
          project_authorizations[:project_id].eq(projects[:id])
          .and(project_authorizations[:user_id].eq(@user.id))
        )
        .join_sources
    end
  end
end
