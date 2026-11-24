# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
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
        return unless previous_traversal_ids.present? && previous_traversal_ids != group.traversal_ids

        in_lock(lease_key, ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER) do
          update_namespace_statistics
        end
      end

      private

      attr_reader :group

      def lease_key
        "namespaces:#{group.id}:update_namespace_statistics_traversal_ids"
      end

      def update_namespace_statistics
        namespace_statistics.each_batch(of: BATCH_SIZE, column: :traversal_ids) do |batch|
          batch.update_all(update_statement)
        end
      end

      def namespace_statistics
        Vulnerabilities::NamespaceStatistic.within(previous_traversal_ids)
      end

      def previous_traversal_ids
        @previous_traversal_ids ||= Vulnerabilities::NamespaceStatistic.by_namespace(group)[0]&.traversal_ids
      end

      def update_statement
        @update_statement ||= begin
          old_prefix = previous_traversal_ids
          new_prefix = group.traversal_ids
          old_length = old_prefix.length

          "traversal_ids = ARRAY[#{new_prefix.join(',')}]::bigint[] || " \
            "traversal_ids[#{old_length + 1}:array_length(traversal_ids, 1)]"
        end
      end
    end
  end
end
