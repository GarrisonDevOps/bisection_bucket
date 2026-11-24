# frozen_string_literal: true

module Tasks
  module Gitlab
    module Geo
      module LogicalReplication
        # Writer detection shared by Gitlab::Geo::PublisherWriteActivityCheck and ReadinessCheck. Plain
        # Ruby so the Rails-free subscription:drop can load it, and outside Gitlab::Geo so loading it
        # there never defines that namespace ahead of Zeitwerk.
        module PublisherSessions
          # Rows the role may not see come back with backend_type NULL. state is NULL for visible
          # background processes too, so backend_type is the reliable blindness signal.
          MASKED_SESSIONS_SQL = <<~SQL
            SELECT count(*) FILTER (WHERE backend_type IS NULL) AS masked_sessions
            FROM pg_catalog.pg_stat_activity
            WHERE datname = current_database()
              AND pid <> pg_catalog.pg_backend_pid()
          SQL

          # Scoped to current_database(): LR is one publisher database per pair (one conninfo, one
          # publication, one subscription). A decomposed ci database would need its own conninfo
          # across every LR task, not only this check.
          #
          # backend_type = 'client backend' excludes walsenders, autovacuum workers and every
          # background worker in one predicate. Aborted transactions can never commit, so they
          # are not listed.
          SESSIONS_SQL = <<~SQL
            SELECT
              a.pid,
              a.usename,
              a.application_name,
              a.client_addr::text AS client_addr,
              a.state,
              (a.backend_xid IS NOT NULL) AS holds_write_transaction,
              EXTRACT(EPOCH FROM (clock_timestamp() - a.xact_start))::int AS transaction_age_seconds,
              left(a.query, 200) AS query
            FROM pg_catalog.pg_stat_activity a
            WHERE a.datname = current_database()
              AND a.pid <> pg_catalog.pg_backend_pid()
              AND a.backend_type = 'client backend'
              AND a.state IN ('active', 'idle in transaction')
            ORDER BY (a.backend_xid IS NOT NULL) DESC, a.xact_start
          SQL

          private

          # PostgreSQL assigns a backend_xid only once a backend has written, so it is proof of a
          # write, and an open transaction can write at any moment. A bare 'active' with no xid is a
          # read-only statement, reported but not blocking, so reads do not fire the gate.
          def blocking_session?(row)
            row['holds_write_transaction'] == 't' || row['state'] == 'idle in transaction'
          end

          def session_description(row)
            age = row['transaction_age_seconds']

            "pid #{row['pid']} (#{row['usename']}/#{row['application_name']}) state=#{row['state']} " \
              "xact_age=#{age ? "#{age}s" : 'n/a'} query=#{row['query'].to_s.inspect}"
          end
        end
      end
    end
  end
end
