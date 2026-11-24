# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class RecalculateNamespaceStatisticsWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :vulnerability_management

      def perform(namespace_id)
        group = Group.find_by_id(namespace_id)

        return unless group.present?

        Vulnerabilities::NamespaceStatistics::RecalculateService.execute(group)
      end
    end
  end
end
