# frozen_string_literal: true

module Vulnerabilities
  module NamespaceHistoricalStatistics
    class UpdateTraversalIdsService
      include Gitlab::ExclusiveLeaseHelpers

      BATCH_SIZE = 100
      LEASE_TTL = 5.minutes
      LEASE_TRY_AFTER = 3.seconds

      def self.execute(group)
        new(group).execute
      end

      def initialize(group)
        @group = group
      end

      def execute
        in_lock(lease_key, ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER) do
          update_historical_statistics
        end
      end

      private

      attr_reader :group

      def lease_key
        "namespaces:#{group.id}:update_historical_statistics_traversal_ids"
      end

      def update_historical_statistics
        historical_statistics.each_batch(of: BATCH_SIZE) do |batch|
          batch.update_all(traversal_ids: group.traversal_ids)
        end
      end

      def historical_statistics
        Vulnerabilities::NamespaceHistoricalStatistic.by_direct_group(group)
      end
    end
  end
end
