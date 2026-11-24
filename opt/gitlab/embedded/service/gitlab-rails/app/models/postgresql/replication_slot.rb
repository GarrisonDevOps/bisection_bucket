# frozen_string_literal: true

module Postgresql
  class ReplicationSlot < Gitlab::Database::SharedModel
    self.table_name = 'pg_replication_slots'

    # Slots created by a subscriber for the initial copy of a table: pg_<suboid>_sync_<relid>_<sysid>
    TABLE_SYNC_SLOT_NAME_PATTERN = '^pg_[0-9]+_sync_[0-9]+_[0-9]+$'

    # Returns true if there are any replication slots in use.
    # PostgreSQL-compatible databases such as Aurora don't support
    # replication slots, so this will return false as well.
    def self.in_use?
      transaction { exists? }
    rescue ActiveRecord::StatementInvalid
      false
    end

    # Returns true if the lag observed across all replication slots exceeds a
    # given threshold.
    #
    # max - The maximum replication lag size, in bytes. Based on GitLab.com
    #       statistics it takes between 1 and 5 seconds to replicate around
    #       100 MB of data.
    def self.lag_too_great?(max = 100.megabytes)
      return false unless in_use?

      lag_function = "pg_wal_lsn_diff" \
        "(pg_current_wal_insert_lsn(), restart_lsn)::bigint"

      # We force the use of a transaction here so the query always goes to the
      # primary, even when using the DB load balancer.
      sizes = transaction { pluck(Arel.sql(lag_function)) }
      too_great = sizes.compact.count { |size| size >= max }

      # If too many replicas are falling behind too much, the availability of a
      # GitLab instance might suffer. To prevent this from happening we require
      # at least 1 replica to have data recent enough.
      if sizes.any? && too_great > 0
        (sizes.length - too_great) <= 1
      else
        false
      end
    end

    def self.count
      connection
        .execute("SELECT COUNT(*) FROM pg_replication_slots;")
        .first
        .fetch('count')
        .to_i
    end

    def self.unused_slots_count
      connection
        .execute("SELECT COUNT(*) FROM pg_replication_slots WHERE active = 'f';")
        .first
        .fetch('count')
        .to_i
    end

    def self.used_slots_count
      connection
        .execute("SELECT COUNT(*) FROM pg_replication_slots WHERE active = 't';")
        .first
        .fetch('count')
        .to_i
    end

    # returns the max number WAL space (in bytes) being used across the replication slots
    def self.max_retained_wal
      connection.execute(<<-SQL.squish).first.fetch('coalesce').to_i
        SELECT COALESCE(MAX(pg_wal_lsn_diff(pg_current_wal_insert_lsn(), restart_lsn)), 0)
          FROM pg_replication_slots;
      SQL
    end

    # Logical slots retain WAL until the subscriber confirms it. inactive_count skips table sync slots (mostly inactive
    # while copying). A lost slot has a NULL restart_lsn, so only lost_count shows it. Returns nil if the query fails,
    # so the Geo gauges keep their last values.
    def self.logical_slots_summary
      connection.execute(<<~SQL.squish).first.symbolize_keys
        SELECT COUNT(*) AS count,
          COUNT(*) FILTER (WHERE NOT active AND slot_name !~ #{connection.quote(TABLE_SYNC_SLOT_NAME_PATTERN)}) AS inactive_count,
          COUNT(*) FILTER (WHERE wal_status = 'lost') AS lost_count,
          COUNT(*) FILTER (WHERE wal_status = 'unreserved') AS unreserved_count,
          COALESCE(MAX(pg_wal_lsn_diff(pg_current_wal_insert_lsn(), restart_lsn)), 0)::bigint AS max_retained_wal_bytes
        FROM pg_replication_slots
        WHERE slot_type = 'logical'
      SQL
    rescue ActiveRecord::StatementInvalid => e
      Gitlab::ErrorTracking.track_exception(e)
      nil
    end

    def self.max_replication_slots
      connection.execute(<<-SQL.squish).first&.fetch('setting').to_i
        SELECT setting FROM pg_settings WHERE name = 'max_replication_slots';
      SQL
    end
  end
end
