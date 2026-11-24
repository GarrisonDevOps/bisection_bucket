# frozen_string_literal: true

module Security
  # rubocop:disable CodeReuse/ActiveRecord -- Finder
  class SecurityPolicyProjectsFinder < BaseContainerService
    SUGGESTION_LIMIT = 20
    SEARCH_SPACE_LIMIT = 250

    def execute
      return Project.none unless ::Security::PolicyAvailability.any_available?(container)

      relation
        .sorted_by_similarity_desc(params[:search], full_path_only: true)
        .limit(SUGGESTION_LIMIT)
    end

    private

    def relation
      case params
      in { search_globally: true, only_linked: true }
        global_linked_projects
      in { search_globally: true }
        global_projects
      in { search_globally: false, only_linked: true }
        contained_linked_projects
      in { search_globally: false }
        contained_projects
      else
        Project.none
      end
    end

    def global_projects
      Project.from_union([
        global_matching_projects,
        base_relation.joins(:route).where(routes: { path: params[:search] }) # always include exact matches
      ])
    end

    def global_matching_projects
      subquery = Route
                   .for_routable_type(Project)
                   .fuzzy_search(params[:search], %i[path])
                   .limit(SEARCH_SPACE_LIMIT)
                   .select(:source_id)

      base_relation.id_in(subquery)
    end

    def global_linked_projects
      subquery_a = base_relation
                     .id_in(Security::OrchestrationPolicyConfiguration.select(:security_policy_management_project_id))
                     .select(:id)

      subquery_b = Route
                     .for_routable_type(Project)
                     .where(source_id: subquery_a)
                     .fuzzy_search(params[:search], %i[path])
                     .select(:source_id)

      Project.id_in(subquery_b)
    end

    def contained_linked_projects
      subquery = Project.id_in(
        Security::OrchestrationPolicyConfiguration
          .for_management_project(container_project_ids)
          .select(:security_policy_management_project_id))

      base_relation
        .id_in(subquery)
        .joins(:route)
        .merge(Route.fuzzy_search(params[:search], %i[path]))
    end

    def contained_projects
      base_relation
        .id_in(container_project_ids)
        .joins(:route)
        .merge(Route.fuzzy_search(params[:search], %i[path]))
    end

    def base_relation
      Project
        .non_archived
        .without_deleted
        .public_or_visible_to_user(current_user, Gitlab::Access::DEVELOPER)
        .in_organization(container.organization)
    end

    def container_project_ids
      container.root_ancestor.all_projects.select(:id)
    end
  end
  # rubocop:enable CodeReuse/ActiveRecord
end
