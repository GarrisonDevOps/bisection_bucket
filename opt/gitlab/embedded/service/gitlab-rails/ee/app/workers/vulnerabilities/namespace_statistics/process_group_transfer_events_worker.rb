# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class ProcessGroupTransferEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:vulnerability_namespace_statistics], 1.minute

      def handle_event(event)
        group = Group.find_by_id(event.data[:group_id])

        return unless group

        Vulnerabilities::NamespaceStatistics::UpdateGroupAncestorsStatisticsService.execute(group)
        Vulnerabilities::NamespaceStatistics::UpdateTraversalIdsService.execute(group)
      end
    end
  end
end
