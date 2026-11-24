# frozen_string_literal: true

module Security
  class SecurityProjectGroupFinder
    include Namespaces::GroupsFilter

    def initialize(project = nil, params = {})
      @project = project
      @params = params
    end

    def execute
      return Group.none unless @project&.security_policy_project_linked_groups

      groups = filter_groups(@project.security_policy_project_linked_groups)
      sort(groups).with_route
    end

    private

    attr_reader :project, :params

    def filter_groups(groups)
      groups = by_ids(groups)
      groups = top_level_only(groups)
      by_search(groups)
    end
  end
end
