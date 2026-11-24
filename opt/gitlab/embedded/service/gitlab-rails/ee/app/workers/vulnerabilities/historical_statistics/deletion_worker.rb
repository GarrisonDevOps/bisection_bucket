# frozen_string_literal: true

module Vulnerabilities
  module HistoricalStatistics
    class DeletionWorker
      include ApplicationWorker

      idempotent!

      # rubocop:disable SidekiqLoadBalancing/WorkerDataConsistency -- preform delete that requires primary DB.
      data_consistency :always
      # rubocop:enable SidekiqLoadBalancing/WorkerDataConsistency

      # rubocop:disable Scalability/CronWorkerContext -- This worker does not perform work scoped to a context.
      include CronjobQueue
      # rubocop:enable Scalability/CronWorkerContext

      feature_category :vulnerability_management

      def perform
        HistoricalStatistics::DeletionService.execute
        NamespaceHistoricalStatistics::DeletionService.execute
      end
    end
  end
end
