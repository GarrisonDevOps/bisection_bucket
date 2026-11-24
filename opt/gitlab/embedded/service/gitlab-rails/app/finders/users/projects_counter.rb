# frozen_string_literal: true

module Users
  class ProjectsCounter
    include Gitlab::Utils::StrongMemoize

    COUNT_LIMIT = 1000

    def initialize(user_ids, organization: nil)
      @user_ids = user_ids
      @organization = organization
    end

    def execute
      return ProjectAuthorization.for_user(user_ids).count_by_user_id unless organization

      limited_organization_counts
    end

    private

    attr_reader :user_ids, :organization

    # Each user's count stops at COUNT_LIMIT + 1, so callers can show "COUNT_LIMIT+" without
    # reading every authorization of users with very large sets.
    # rubocop: disable CodeReuse/ActiveRecord -- requires specialized queries for optimization
    def limited_organization_counts
      counts = "SELECT COUNT(*) AS count FROM (#{organization_authorizations.to_sql}) limited"

      User.with(organization_projects_cte.to_arel)
        .where(id: user_ids)
        .joins("CROSS JOIN LATERAL (#{counts}) counts")
        .limit(user_ids.size)
        .pluck(:id, Arel.sql('counts.count'))
        .to_h
    end

    def organization_authorizations
      authorizations = ProjectAuthorization.arel_table

      ProjectAuthorization
        .where(authorizations[:user_id].eq(User.arel_table[:id]))
        .where(authorizations[:project_id].in(organization_projects_cte.table.project(:id)))
        .select(1)
        .limit(COUNT_LIMIT + 1)
    end

    # Lets the planner use the projects organization index instead of filtering projects by primary key.
    def organization_projects_cte
      Gitlab::SQL::CTE.new(
        :organization_projects,
        Project.in_organization(organization).select(:id),
        materialized: false
      )
    end
    strong_memoize_attr :organization_projects_cte
    # rubocop: enable CodeReuse/ActiveRecord
  end
end
