# frozen_string_literal: true

module Ci
  module Runners
    # Counts pending loose foreign key records of runner managers in the active partition only: scanning older
    # partitions, as Gitlab::Database::LooseForeignKeysBacklogChecker does, can take seconds.
    # The runner tables have no sharding key, so their records stay in LooseForeignKeys::DeletedRecord (#597949).
    class LooseForeignKeysBacklog
      # Only the table the callers delete from. The cleanup worker takes ci_runners and ci_runner_machines in turn,
      # so a ci_runners backlog slows these records but doesn't stop them, and pausing wouldn't reduce it.
      TABLES = %w[public.ci_runner_machines].freeze

      # Returns the number of pending records, counting at most `limit` records.
      def pending_count(limit:)
        Gitlab::Database::SharedModel.using_connection(::Ci::ApplicationRecord.connection) do
          partition = ::LooseForeignKeys::DeletedRecord.partitioning_strategy.active_partition

          if partition
            ::LooseForeignKeys::DeletedRecord
              .status_pending
              .for_partition(partition.value)
              .for_table(TABLES)
              .limit(limit)
              .count
          else
            0
          end
        end
      end

      # True when more than `limit` records are pending, or when the count could not be read in time: callers
      # should stop deleting rather than add to a backlog they cannot see.
      def over_limit?(limit)
        pending_count(limit: limit + 1) > limit
      rescue ActiveRecord::QueryCanceled # rubocop:disable Database/RescueQueryCanceled -- an unknown backlog is treated as too large
        true
      end
    end
  end
end
