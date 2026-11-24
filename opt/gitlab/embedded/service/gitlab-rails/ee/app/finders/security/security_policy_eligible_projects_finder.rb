# frozen_string_literal: true

module Security
  # Finds all projects eligible for policy scope selection for a given
  # Security Policy Project (SPP). Collects root ancestors of all linked
  # groups, then returns all projects under those root namespaces.
  #
  # This ensures sibling and parent-level projects are visible, not just
  # descendants of each linked group.
  class SecurityPolicyEligibleProjectsFinder
    def initialize(current_user, security_policy_project, params = {})
      @current_user = current_user
      @security_policy_project = security_policy_project
      @params = params
    end

    def execute
      return Project.none unless security_policy_project
      return Project.none unless licensed?

      by_search(filter_by_ids(eligible_projects))
    end

    private

    attr_reader :current_user, :security_policy_project, :params

    def licensed?
      ::Security::PolicyAvailability.any_available?(security_policy_project)
    end

    def eligible_projects
      root_ids = root_ancestor_ids
      return Project.none if root_ids.empty?

      Project
        .id_in(project_ids_in_scope(root_ids))
        .without_deleted
        .public_or_visible_to_user(current_user)
    end

    # Per-namespace `all_unarchived_project_ids` hits the
    # `Namespaces::Traversal::Cached` lookup which falls back to a
    # recursive query when the cache is cold.
    def project_ids_in_scope(root_ids)
      relations = Namespace.id_in(root_ids).map(&:all_unarchived_project_ids)

      return relations.first if relations.one?

      Project.from_union(relations)
    end

    def root_ancestor_ids
      Namespace.root_ids_for(security_policy_project.security_policy_project_linked_groups)
    end

    def by_search(projects)
      return projects if params[:search].blank?

      projects.search(params[:search])
    end

    def filter_by_ids(projects)
      return projects if params[:ids].blank?

      projects.id_in(params[:ids])
    end
  end
end
