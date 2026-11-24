# frozen_string_literal: true

module Security
  module InventoryFilters
    class UpdateTraversalIdsService
      PROJECT_BATCH_SIZE = 100

      def self.execute(project_ids)
        new(project_ids).execute
      end

      def initialize(project_ids)
        @project_ids = project_ids
      end

      def execute
        return if project_ids.blank?

        project_ids.sort.each_slice(PROJECT_BATCH_SIZE) do |batch|
          Project.group_by_namespace_traversal_ids(batch).each do |traversal_ids, batch_project_ids|
            Security::InventoryFilter.by_project_id(batch_project_ids).update_all(traversal_ids: traversal_ids)
          end
        end
      end

      private

      attr_reader :project_ids
    end
  end
end
