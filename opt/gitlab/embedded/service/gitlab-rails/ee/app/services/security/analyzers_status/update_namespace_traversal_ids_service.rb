# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class UpdateNamespaceTraversalIdsService
      BATCH_SIZE = 100

      def self.execute(group)
        new(group).execute
      end

      def initialize(group)
        @group = group
      end

      def execute
        return unless previous_traversal_ids.present? && previous_traversal_ids != group.traversal_ids

        update_analyzer_statuses
      end

      private

      attr_reader :group

      def update_analyzer_statuses
        analyzer_statuses.each_batch(of: BATCH_SIZE, column: :traversal_ids) do |batch|
          batch.update_all(update_statement)
        end
      end

      def analyzer_statuses
        Security::AnalyzerNamespaceStatus.within(previous_traversal_ids)
      end

      def previous_traversal_ids
        @previous_traversal_ids ||= group.analyzer_group_statuses[0]&.traversal_ids
      end

      def update_statement
        # Replace the old traversal_ids prefix with the new prefix while keeping the suffix ids after the changed part
        @update_statement ||= begin
          old_prefix = previous_traversal_ids
          new_prefix = group.traversal_ids
          old_length = old_prefix.length

          "traversal_ids = ARRAY[#{new_prefix.join(',')}]::bigint[] || " \
            "traversal_ids[#{old_length + 1}:array_length(traversal_ids, 1)]"
        end
      end
    end
  end
end
