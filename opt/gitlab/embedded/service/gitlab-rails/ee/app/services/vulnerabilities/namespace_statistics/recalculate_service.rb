# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class RecalculateService
      def self.execute(group)
        new(group).execute
      end

      def initialize(group)
        @group = group
      end

      def execute
        return unless group.present?

        # recalculating for the group namespace should return a single diff in case of actual statistics difference
        namespace_diffs = AdjustmentService.new([group.id]).execute
        return unless namespace_diffs.present? && namespace_diffs.length == 1

        ancestors_diff = get_ancestors_diff(namespace_diffs)
        return unless ancestors_diff.present?

        # Propagate the change to the group ancestors
        UpdateService.execute([ancestors_diff])
      end

      private

      attr_reader :group

      def get_ancestors_diff(namespace_diffs)
        # Remove the project's group which has already have the updated value due to the AdjustmentService.
        # Create a diff for its ancestors only
        namespace_diff = namespace_diffs.first
        ids = namespace_diff["traversal_ids"].gsub(/[{}]/, '').split(',').map(&:to_i)
        return unless ids.length > 1

        ids.pop # remove the project's group id
        namespace_diff["namespace_id"] = ids.last
        namespace_diff["traversal_ids"] = "{#{ids.join(',')}}"

        namespace_diff
      end
    end
  end
end
