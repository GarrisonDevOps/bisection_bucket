# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class ProcessProjectTransferEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:vulnerability_namespace_statistics], 1.minute

      def handle_event(event)
        project = Project.find_by_id(event.data[:project_id])

        return unless project

        Vulnerabilities::NamespaceStatistics::UpdateProjectAncestorsStatisticsService.execute(project)
      end
    end
  end
end
