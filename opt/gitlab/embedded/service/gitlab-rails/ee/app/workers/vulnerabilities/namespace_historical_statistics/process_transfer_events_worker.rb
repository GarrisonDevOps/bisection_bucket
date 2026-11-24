# frozen_string_literal: true

module Vulnerabilities
  module NamespaceHistoricalStatistics
    class ProcessTransferEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :vulnerability_management

      def handle_event(event)
        group = Group.find_by_id(event.data[:group_id])

        return unless group

        Vulnerabilities::NamespaceHistoricalStatistics::ScheduleUpdatingTraversalIdsForHierarchyService.execute(group)
      end
    end
  end
end
