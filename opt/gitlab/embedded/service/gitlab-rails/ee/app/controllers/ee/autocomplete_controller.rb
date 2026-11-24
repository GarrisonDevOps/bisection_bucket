# frozen_string_literal: true

module EE
  module AutocompleteController
    extend ::ActiveSupport::Concern

    prepended do
      feature_category :groups_and_projects, [:project_routes, :project_groups, :namespace_routes, :group_subgroups]
      urgency :high, [:project_groups]
    end

    def project_groups
      groups = ::Autocomplete::ProjectInvitedGroupsFinder
        .new(current_user, project_invited_groups_finder_params)
        .execute

      render json: ::Autocomplete::GroupSerializer.new.represent(groups)
    end

    def group_subgroups
      groups = ::Autocomplete::GroupSubgroupsFinder
        .new(current_user, group_subgroups_finder_params)
        .execute

      render json: ::Autocomplete::GroupSerializer.new.represent(groups)
    end

    def project_routes
      routes = ::Autocomplete::RoutesFinder::ProjectsOnly
                 .new(current_user, routes_finder_params)
                 .execute

      render json: RouteSerializer.new.represent(routes)
    end

    def namespace_routes
      routes = ::Autocomplete::RoutesFinder::NamespacesOnly
                 .new(current_user, routes_finder_params)
                 .execute

      render json: RouteSerializer.new.represent(routes)
    end

    private

    def project_invited_groups_finder_params
      params.permit(:with_project_access, :project_id, :search, :parent)
    end

    def group_subgroups_finder_params
      params.permit(:include_parent_descendants, :include_parent_shared_groups, :group_id, :search)
    end

    def routes_finder_params
      params.permit(:search)
    end

    def suggested_users_params
      params.permit(:search, :merge_request_iid, :approval_rules, :target_branch)
    end

    def suggested_reviewers_available?
      project.can_suggest_reviewers?
    end

    def presented_suggested_users
      return [] unless suggested_users_params[:search].blank? && suggested_users_params[:merge_request_iid].present?
      return [] unless suggested_reviewers_available?

      merge_request = project.merge_requests.find_by_iid!(suggested_users_params[:merge_request_iid])
      return [] unless merge_request&.open?

      suggested_users = merge_request.suggested_reviewer_users
      return [] if suggested_users.empty?

      ::UserSerializer
        .new(suggested_users_params.merge({ current_user: current_user, suggested: true }))
        .represent(suggested_users, project: project)
    end
  end
end
