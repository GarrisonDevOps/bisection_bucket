# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class UpdateArchivedService
      def self.execute(projects)
        new(projects).execute
      end

      def initialize(projects)
        @projects = Array(projects)
      end

      def execute
        archived, unarchived = projects.partition(&:self_or_ancestors_archived?)

        update_archived(archived.map(&:id), true)
        update_archived(unarchived.map(&:id), false)
      end

      private

      attr_reader :projects

      def update_archived(ids, archived)
        return if ids.empty?

        Security::AnalyzerProjectStatus.update_archived_for(ids, archived: archived)
        Security::InventoryFilter.update_archived_for(ids, archived: archived)
      end
    end
  end
end
