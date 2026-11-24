# frozen_string_literal: true

module Security
  module InventoryFilters
    module ProjectAttributes
      private

      def build_project_attributes(projects)
        projects.index_by(&:id).transform_values do |project|
          {
            project_name: project.name,
            traversal_ids: project.namespace.traversal_ids,
            archived: project.archived
          }
        end
      end
    end
  end
end
