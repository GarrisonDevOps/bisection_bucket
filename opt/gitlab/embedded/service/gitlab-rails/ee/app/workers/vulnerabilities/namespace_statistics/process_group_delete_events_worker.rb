# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class ProcessGroupDeleteEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      concurrency_limit -> { 25 }
      defer_on_database_health_signal :gitlab_sec, [:vulnerability_namespace_statistics], 1.minute

      BATCH_SIZE = 500

      def handle_event(event)
        parent_group = Group.find_by_id(event.data[:parent_namespace_id])
        return unless parent_group

        # Deleting a group triggers async delete with loose foreign keys of related vulnerability_statistics records.
        # Since RecalculateService requires these records to be completely removed,
        # we must ensure no records exists before triggering recalculation
        batch_delete_statistics_records(parent_group, event.data[:group_id])
        Vulnerabilities::NamespaceStatistics::RecalculateService.execute(parent_group)
      end

      def batch_delete_statistics_records(parent_group, deleted_group_id)
        loop do
          count = group_projects_statistics(parent_group, deleted_group_id).limit(BATCH_SIZE).delete_all
          break if count < BATCH_SIZE
        end
      end

      def group_projects_statistics(parent_group, deleted_group_id)
        @statistics_relation ||= begin
          traversal_ids = parent_group.traversal_ids + [deleted_group_id]

          Statistic.unarchived.within(traversal_ids)
        end
      end
    end
  end
end
