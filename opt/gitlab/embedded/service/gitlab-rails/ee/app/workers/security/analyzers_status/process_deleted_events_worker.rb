# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class ProcessDeletedEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      concurrency_limit -> { 25 }
      defer_on_database_health_signal :gitlab_sec, [:analyzer_namespace_statuses], 1.minute

      def handle_event(event)
        project_id = event.data[:project_id]
        namespace_id = event.data[:namespace_id]

        group = Group.find_by_id(namespace_id)
        return unless project_id && group.present?

        # Deleting project triggers async delete with loose foreign keys. Verify no records exist before recalculating
        AnalyzerProjectStatus.by_projects(project_id).delete_all
        Security::AnalyzerNamespaceStatuses::RecalculateWorker.perform_in(
          Security::AnalyzerNamespaceStatuses::RecalculateWorker::RECALCULATE_DELAY,
          group.id
        )
      end
    end
  end
end
