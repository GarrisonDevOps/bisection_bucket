# frozen_string_literal: true

module Gitlab
  module Database
    module Partitioning
      # ATTACH PARTITION locks the tables that the partitioned table references through foreign keys.
      # Syncs of different tables can lock the same table, so only one sync runs per database.
      class DatabaseSyncLease
        include AsyncDdlExclusiveLeaseGuard

        LEASE_TIMEOUT = 1.hour

        attr_reader :database_config_name

        def initialize(database_name)
          @database_config_name = database_name
        end

        def renew
          return true if renew_lease!

          Gitlab::AppJsonLogger.warn(
            message: "Lost the partition sync lease of the #{database_config_name} database.",
            lease_key: lease_key,
            database_name: database_config_name
          )

          false
        end

        private

        def lease_timeout
          LEASE_TIMEOUT
        end

        # Reindexing can hold the lease for hours, so a skipped sync is not an error.
        def lease_taken_log_level
          :warn
        end

        def lease_taken_message
          "Skipping partition sync: another DDL action holds the lease of the #{database_config_name} database."
        end
      end
    end
  end
end
