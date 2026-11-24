# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class ProcessProjectDeleteEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      concurrency_limit -> { 25 }
      defer_on_database_health_signal :gitlab_sec, [:vulnerability_namespace_statistics], 1.minute

      def handle_event(event)
        project_id = event.data[:project_id]
        group = Group.find_by_id(event.data[:namespace_id])

        return unless project_id && group.present?

        # Deleting a project triggers async delete with loose foreign keys of related vulnerability_statistics records.
        # Since RecalculateService requires these records to be completely removed,
        # we must ensure no records exists before triggering recalculation
        Statistic.by_projects(project_id).delete_all
        Vulnerabilities::NamespaceStatistics::RecalculateService.execute(group)
      end
    end
  end
end
