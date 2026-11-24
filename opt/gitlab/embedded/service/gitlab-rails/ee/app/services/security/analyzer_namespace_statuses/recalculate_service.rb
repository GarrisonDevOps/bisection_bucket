# frozen_string_literal: true

module Security
  module AnalyzerNamespaceStatuses
    class RecalculateService
      def self.execute(group)
        new(group).execute
      end

      def initialize(group)
        @group = group
      end

      def execute
        return unless group.present?

        # recalculating for the group namespace could return a diff for each analyzer type
        # in case of actual status difference
        namespace_diffs = AdjustmentService.new([group.id]).execute
        return unless namespace_diffs.present? && !namespace_diffs.empty?

        ancestors_diffs_with_metadata = get_ancestors_diffs_with_metadata(namespace_diffs)
        return unless ancestors_diffs_with_metadata.present?

        # Propagate the change to the group ancestors
        AncestorsUpdateService.execute(ancestors_diffs_with_metadata)
      end

      private

      attr_reader :group

      def get_ancestors_diffs_with_metadata(namespace_diffs)
        # Remove the project's group which has already have the updated value due to the AdjustmentService.
        # Create a diff for its ancestors only
        first_diff = namespace_diffs.first

        traversal_ids = first_diff["traversal_ids"].gsub(/[{}]/, '').split(',').map(&:to_i)
        return unless traversal_ids.length > 1

        traversal_ids.pop # remove group id since it was already adjusted using the AdjustmentService
        namespace_id = traversal_ids.last

        {
          diff: build_diffs(namespace_diffs),
          namespace_id: namespace_id,
          traversal_ids: traversal_ids
        }
      end

      def build_diffs(namespace_diffs)
        diffs = {}

        namespace_diffs.each do |diff|
          # Find the analyzer type name from the enum
          analyzer_name = Enums::Security.analyzer_types_for_status.key(diff["analyzer_type"])

          diffs[analyzer_name] = {
            "success" => diff["success"],
            "failed" => diff["failure"],
            "stale" => diff["stale"]
          }
        end

        diffs
      end
    end
  end
end
