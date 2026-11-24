# frozen_string_literal: true

module Gitlab
  module Database
    module Diagnostics
      module Checks
        class PlannerStatistics < Base
          MISSING = 'missing'
          STALE = 'stale'
          STATUS_ORDER = { MISSING => 0, STALE => 1, nil => 2 }.freeze

          TABLE = 'table'
          PARTITIONED_TABLE = 'partitioned_table'

          # Below this size the planner copes without statistics, and on a fresh
          # install most tables sit there unanalyzed, so they are left out.
          SIZE_FLOOR_BYTES = 10 * 1024 * 1024 # 10 MiB
          RELATIONS_LIMIT = 50

          # Candidates ranked by heap size, the cheap stand-in for relpages, which stays
          # 0 as long as reltuples is -1; only these join the statistics view
          CANDIDATE_LIMIT = 100

          # Slack over the interval for the worker's schedule and the ANALYZE itself
          STALE_INTERVAL_MULTIPLIER = 2

          STATS_RESET_SQL = 'SELECT stats_reset FROM pg_stat_database WHERE datname = current_database()'

          STATISTICS_COLUMNS_SQL = <<~SQL.chomp
            s.last_analyze,
            s.last_autoanalyze,
            EXTRACT(EPOCH FROM (clock_timestamp() - GREATEST(s.last_analyze, s.last_autoanalyze)))::bigint
              AS analyze_age_seconds
          SQL

          # Ordinary tables, leaf partitions included, that were never analyzed: reltuples stays -1
          # until then and, unlike pg_stat, is not lost to a crash or a reset. VACUUM and CREATE INDEX
          # set it too but write no statistics, which is how every table comes out of a restore.
          NEVER_ANALYZED_TABLES_SQL = <<~SQL
            WITH candidates AS (
              SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name,
                pg_relation_size(c.oid) AS heap_bytes
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relkind = 'r'
                AND n.nspname NOT IN ('pg_catalog', 'pg_toast', 'information_schema')
                AND (
                  c.reltuples = -1
                  OR (
                    -- pg_statistic is readable by superusers only, hence pg_stats, which hides tables the role
                    -- cannot read; ownership, the floor and the analyze time skip tables that cannot be findings
                    c.reltuples > 0
                    AND pg_has_role(c.relowner, 'USAGE')
                    AND c.relpages::bigint * current_setting('block_size')::int >= #{SIZE_FLOOR_BYTES}
                    AND pg_stat_get_last_analyze_time(c.oid) IS NULL
                    AND pg_stat_get_last_autoanalyze_time(c.oid) IS NULL
                    AND NOT EXISTS (
                      SELECT 1 FROM pg_stats st WHERE st.schemaname = n.nspname AND st.tablename = c.relname
                    )
                  )
                )
              ORDER BY heap_bytes DESC
              LIMIT #{CANDIDATE_LIMIT}
            )
            SELECT schema_name,
              table_name,
              heap_bytes,
              s.n_mod_since_analyze AS modifications_since_analyze,
              #{STATISTICS_COLUMNS_SQL}
            FROM candidates
            LEFT JOIN pg_stat_user_tables s ON s.relid = candidates.oid
          SQL
          .freeze

          # Every partitioned table, sized as the heap of its partition tree: the parent
          # has no storage of its own, and totals with every index cost several times more.
          PARTITIONED_TABLES_SQL = <<~SQL
            SELECT n.nspname AS schema_name,
              c.relname AS table_name,
              c.reltuples,
              (SELECT sum(pg_relation_size(relid)) FROM pg_partition_tree(c.oid)) AS heap_bytes,
              #{STATISTICS_COLUMNS_SQL}
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
            WHERE c.relkind = 'p'
              AND n.nspname NOT IN ('pg_catalog', 'pg_toast', 'information_schema')
          SQL
          .freeze

          def execute
            {
              stats_reset: connection.select_value(STATS_RESET_SQL),
              relations: relations.first(RELATIONS_LIMIT),
              relations_capped: relations.size > RELATIONS_LIMIT
            }.merge(verdict([missing_finding, stale_finding].compact))
          end

          private

          # Problems first, then by size, so the limit cuts healthy rows before any finding's subject.
          def relations
            @relations ||= (never_analyzed_tables + partitioned_tables)
              .select { |relation| relation[:heap_bytes] >= SIZE_FLOOR_BYTES }
              .sort_by { |relation| [STATUS_ORDER.fetch(relation[:status]), -relation[:heap_bytes]] }
          end

          def never_analyzed_tables
            connection.select_all(NEVER_ANALYZED_TABLES_SQL).map do |row|
              relation_row(row, TABLE).merge(
                modifications_since_analyze: row['modifications_since_analyze'].to_i,
                status: MISSING
              )
            end
          end

          def partitioned_tables
            connection.select_all(PARTITIONED_TABLES_SQL).map do |row|
              interval = analyze_intervals[row['table_name']] || Partitioning::BaseStrategy::DEFAULT_ANALYZE_INTERVAL

              relation_row(row, PARTITIONED_TABLE).merge(
                estimated_rows: estimated_rows(row),
                analyze_interval: interval.to_i,
                status: partitioned_status(row, interval)
              )
            end
          end

          def relation_row(row, kind)
            {
              schema_name: row['schema_name'],
              table_name: row['table_name'],
              kind: kind,
              heap_bytes: row['heap_bytes'].to_i,
              last_analyze: row['last_analyze'],
              last_autoanalyze: row['last_autoanalyze'],
              analyze_age_seconds: row['analyze_age_seconds']&.to_i
            }
          end

          # nil, not 0, when the table was never analyzed: the count is unknown
          def estimated_rows(row)
            reltuples = row['reltuples'].to_f

            reltuples < 0 ? nil : reltuples.to_i
          end

          # A nil age means the timestamps were lost to a stats reset, not that the
          # table is stale: reltuples still proves it was analyzed at some point.
          def partitioned_status(row, interval)
            return MISSING if row['reltuples'].to_f < 0

            age = row['analyze_age_seconds']&.to_i
            return unless age

            STALE if age > interval.to_i * STALE_INTERVAL_MULTIPLIER
          end

          # Tables the partition manager analyzes on a schedule. Autovacuum skips
          # partitioned tables, so any other one is analyzed by hand only and is
          # held to the manager's default interval.
          def analyze_intervals
            @analyze_intervals ||= Partitioning.registered_for_sync.to_h do |model|
              [model.table_name, model.partitioning_strategy.analyze_interval]
            end
          end

          def missing_finding
            count = relations.count { |relation| relation[:status] == MISSING }
            return if count == 0

            {
              severity: Findings::ERROR,
              code: 'statistics_missing',
              message: missing_tables_capped? ? capped_missing_message(count) : missing_message(count)
            }
          end

          # Every candidate cleared the floor, so the limit may have cut off more tables
          # above it, as it does after a major version upgrade.
          def missing_tables_capped?
            relations.count { |relation| relation[:kind] == TABLE } == CANDIDATE_LIMIT
          end

          def missing_message(count)
            format(ns_(
              'DatabaseDiagnostics|%{count} large table has no planner statistics, so PostgreSQL can choose ' \
                'bad query plans for it. Run ANALYZE on it in a session with statement_timeout set to 0. ANALYZE ' \
                'on a partitioned table covers its partitions as well and can take a long time.',
              'DatabaseDiagnostics|%{count} large tables have no planner statistics, so PostgreSQL can choose ' \
                'bad query plans for them. Run ANALYZE on each in a session with statement_timeout set to 0. ' \
                'ANALYZE on a partitioned table covers its partitions as well and can take a long time.',
              count), count: count)
          end

          def capped_missing_message(count)
            format(ns_(
              'DatabaseDiagnostics|At least %{count} large table has no planner statistics, so PostgreSQL can ' \
                'choose bad query plans for it. Run ANALYZE with no table name, in a session with ' \
                'statement_timeout set to 0, to cover the whole database. It can take a long time.',
              'DatabaseDiagnostics|At least %{count} large tables have no planner statistics, so PostgreSQL can ' \
                'choose bad query plans for them. Run ANALYZE with no table name, in a session with ' \
                'statement_timeout set to 0, to cover the whole database. It can take a long time.',
              count), count: count)
          end

          def stale_finding
            count = relations.count { |relation| relation[:status] == STALE }
            return if count == 0

            {
              severity: Findings::WARNING,
              code: 'partitioned_statistics_stale',
              message: format(ns_(
                'DatabaseDiagnostics|%{count} partitioned table was last analyzed more than twice its expected ' \
                  'interval ago. Autovacuum never analyzes a partitioned table, so run ANALYZE on it in a session ' \
                  'with statement_timeout set to 0. ANALYZE also samples every partition and can take a long time.',
                'DatabaseDiagnostics|%{count} partitioned tables were last analyzed more than twice their expected ' \
                  'interval ago. Autovacuum never analyzes a partitioned table, so run ANALYZE on each in a session ' \
                  'with statement_timeout set to 0. ANALYZE also samples every partition and can take a long time.',
                count), count: count)
            }
          end
        end
      end
    end
  end
end
