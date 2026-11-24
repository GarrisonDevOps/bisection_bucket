# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class BaseUpdateAncestorsService
      def self.execute(group_or_project)
        new(group_or_project).execute
      end

      def initialize(group_or_project)
        @group_or_project = group_or_project
      end

      def execute
        return unless analyzer_statuses.present?

        Security::AnalyzerNamespaceStatus.transaction do
          reduce_from_old_ancestors
          add_to_new_ancestors
        end
      end

      private

      attr_reader :group_or_project

      def reduce_from_old_ancestors
        reduce_diffs = diffs(nil, -1)
        AnalyzerNamespaceStatuses::AncestorsUpdateService.execute(reduce_diffs)
      end

      def add_to_new_ancestors
        increase_diffs = diffs(namespace.traversal_ids)
        AnalyzerNamespaceStatuses::AncestorsUpdateService.execute(increase_diffs)
      end

      def analyzer_statuses
        raise NotImplementedError
      end

      def diffs(traversal_ids, statuses_counters_coefficient = 1)
        raise NotImplementedError
      end

      def namespace
        raise NotImplementedError
      end
    end
  end
end
