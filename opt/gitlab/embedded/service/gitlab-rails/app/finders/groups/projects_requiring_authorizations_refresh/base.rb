# frozen_string_literal: true

module Groups
  module ProjectsRequiringAuthorizationsRefresh
    class Base
      def initialize(group)
        @group = group
      end

      private

      def ids_of_projects_in_hierarchy_and_project_shares(group)
        project_ids = Set.new

        ids_of_projects_in_hierarchy = group.all_projects.pluck(:id) # rubocop: disable CodeReuse/ActiveRecord
        ids_of_projects_in_project_shares = ids_of_projects_shared_with_self_and_descendant_groups(group)

        project_ids.merge(ids_of_projects_in_hierarchy)
        project_ids.merge(ids_of_projects_in_project_shares)

        project_ids
      end

      # One query, not one per batch of groups: a subtree can hold over 100k groups.
      def ids_of_projects_shared_with_self_and_descendant_groups(group)
        ProjectGroupLink.in_group(group.self_and_descendants.select(:id)).distinct.pluck(:project_id) # rubocop: disable CodeReuse/ActiveRecord -- one-off ID lookup used only by this finder
      end
    end
  end
end
