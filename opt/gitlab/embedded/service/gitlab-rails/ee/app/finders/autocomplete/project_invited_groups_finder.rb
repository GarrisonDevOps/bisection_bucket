# frozen_string_literal: true

module Autocomplete
  class ProjectInvitedGroupsFinder
    include ::Namespaces::GroupsFilter

    attr_reader :current_user, :params

    # current_user - The User object of the user that wants to view the list of
    #                projects.
    #
    # params - A Hash containing additional parameters to set.
    #          The supported parameters are those supported by `Autocomplete::ProjectFinder`.
    def initialize(current_user, params = {})
      @current_user = current_user
      @params = params
    end

    # rubocop: disable CodeReuse/Finder
    def execute
      project = ::Autocomplete::ProjectFinder
        .new(current_user, params)
        .execute

      return Group.none unless project

      groups = invited_groups(project)
      by_search(groups)
    end
    # rubocop: enable CodeReuse/Finder

    private

    def invited_groups(project)
      invited_groups = project.invited_groups

      return invited_groups if with_project_access?(project)

      Group.from_union([
        invited_groups.public_to_user(current_user),
        invited_groups.for_authorized_group_members(current_user)
      ])
    end

    def with_project_access?(project)
      return false unless params[:with_project_access].present?

      project.member?(current_user, Gitlab::Access::MAINTAINER)
    end
  end
end
