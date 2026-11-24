# frozen_string_literal: true

module Vulnerabilities
  module NamespaceHistoricalStatistics
    class UpdateTraversalIdsWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      data_consistency :sticky

      feature_category :vulnerability_management

      def perform(group_id)
        group = Group.find_by_id(group_id)

        return unless group

        Vulnerabilities::NamespaceHistoricalStatistics::UpdateTraversalIdsService.execute(group)
      end
    end
  end
end
