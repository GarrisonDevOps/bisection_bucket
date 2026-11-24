# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class ProcessArchivedEventsWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :sticky
      idempotent!
      deduplicate :until_executing, including_scheduled: true

      feature_category :security_asset_inventories
      concurrency_limit -> { 25 }
      defer_on_database_health_signal :gitlab_sec, [:analyzer_namespace_statuses], 1.minute

      def handle_event(event)
        project_id = event.data[:project_id]
        namespace_id = event.data[:namespace_id]

        handle_project_related_records(project_id)
        handle_namespace_related_records(namespace_id)
      end

      def handle_project_related_records(project_id)
        project = Project.find_by_id(project_id)
        return unless project

        UpdateArchivedService.execute(project)
      end

      def handle_namespace_related_records(namespace_id)
        group = Group.find_by_id(namespace_id)
        return unless group.present?

        Security::AnalyzerNamespaceStatuses::RecalculateWorker.perform_in(
          Security::AnalyzerNamespaceStatuses::RecalculateWorker::RECALCULATE_DELAY,
          group.id
        )
      end
    end
  end
end
