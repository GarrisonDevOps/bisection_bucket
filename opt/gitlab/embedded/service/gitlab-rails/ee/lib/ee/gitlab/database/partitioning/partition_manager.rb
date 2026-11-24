# frozen_string_literal: true

module EE
  module Gitlab
    module Database
      module Partitioning
        module PartitionManager
          extend ::Gitlab::Utils::Override
          include ::Gitlab::Utils::StrongMemoize

          private

          # A database fed by logical replication only creates partitions: detaching could remove a range the
          # publisher still writes to, and changing the parent takes an ACCESS EXCLUSIVE lock that stalls the
          # apply worker.
          override :logical_replication_subscriber?
          def logical_replication_subscriber?
            geo_node_table_exists? && ::Gitlab::Geo::LogicalReplication.subscriber?(connection)
          end
          strong_memoize_attr :logical_replication_subscriber?

          # Not Gitlab::Geo.connected?: Rails opens connections lazily, and it reports one that has not
          # run a query yet as inactive, which would turn replica mode off for the first model synced on it.
          def geo_node_table_exists?
            ::GeoNode.table_exists?
          rescue ActiveRecord::ActiveRecordError, PG::Error
            false
          end
        end
      end
    end
  end
end
