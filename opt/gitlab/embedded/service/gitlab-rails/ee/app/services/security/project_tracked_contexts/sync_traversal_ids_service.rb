# frozen_string_literal: true

module Security
  module ProjectTrackedContexts
    class SyncTraversalIdsService
      def self.execute(project_id)
        new(project_id).execute
      end

      def initialize(project_id)
        @project_id = project_id
      end

      def execute
        return unless project

        update_tracked_contexts
      end

      private

      attr_reader :project_id

      def project
        @project ||= Project.find_by_id(project_id)
      end

      def traversal_ids
        @traversal_ids ||= project.namespace.traversal_ids
      end

      def update_tracked_contexts
        project.security_project_tracked_contexts
          .with_traversal_ids_other_than(traversal_ids)
          .update_all(traversal_ids: traversal_ids)
      end
    end
  end
end
