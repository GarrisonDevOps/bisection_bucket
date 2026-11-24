# frozen_string_literal: true

module Gitlab
  module Database
    module PgAsh
      # Reads pg_ash active session history for one window of the database
      # behind the connection. pg_ash samples every database on the server,
      # so each read filters on current_database().
      class Report
        InvalidWindowError = Class.new(StandardError)
        QueryDetailsUnavailableError = Class.new(StandardError)

        # pg_ash reads its minute rollups only for windows longer than an hour,
        # and reading raw samples for an hour takes seconds on a busy primary.
        # The overview (wait event types, top queries, timeline) covers more than an hour,
        # so it reads the rollups unless they lag behind the window.
        OVERVIEW = { default: 61.minutes, allowed: (61.minutes)..(24.hours) }.freeze

        # The queries behind a wait event type only come from raw samples, whose
        # cost grows with the window, so the drill-down covers a few minutes.
        DRILL_DOWN = { default: 5.minutes, allowed: (1.minute)..(5.minutes) }.freeze

        # pg_ash keeps minute rollups for 30 days by default, counted back from the newest one,
        # because the cleanup job stops with sampling. Older windows fall back to hourly
        # rollups, which change the period a read covers.
        MAX_LOOKBACK = 30.days

        # The reads of one report share the budget that ApplicationRecord.with_fast_read_statement_timeout
        # gives one statement, so they stay within the 5 s target of a low urgency endpoint.
        # That helper can fall back to a replica, but query text comes from pg_stat_statements on the primary only.
        READ_BUDGET_MS = 4_500

        AAS_COLUMNS = %i[avg_aas peak_aas p99_aas].freeze
        TOP_COLUMNS = [*AAS_COLUMNS, :pct].freeze

        WAIT_EVENT_TYPE_LIMIT = 20
        QUERY_LIMIT = 10
        QUERY_TEXT_LIMIT = 1_000

        # pg_ash raises this when raw samples no longer cover the window, so
        # load can no longer be attributed to queries.
        RAW_ATTRIBUTION_UNAVAILABLE = 'pg_ash: this drill needs exact raw query attribution'

        # Builds the window a read covers, aligned to whole minutes like the
        # pg_ash readers.
        #
        # @param kind [Hash] {OVERVIEW} or {DRILL_DOWN}
        # @param from [String, nil] ISO 8601 start; nil with to for the default
        # @param to [String, nil] ISO 8601 end
        # @param latest_end [Time, nil] the latest end allowed, such as {.rollup_watermark}
        # @param newest_rollup [Time, nil] {.rollup_watermark}, which the 30 days count back from;
        #   defaults to latest_end
        # @param now [Time]
        # @return [Range<Time>] a window ending after latest_end or a minute ago
        #   ends there instead, and one shorter than the kind allows starts earlier
        # @raise [InvalidWindowError] when the window is malformed, starts at or
        #   after its requested end, is too long, or starts over 30 days before the newest rollup,
        #   or over 30 days before a minute ago when there is none
        def self.window(kind, from: nil, to: nil, latest_end: nil, newest_rollup: latest_end, now: Time.current)
          # pg_ash rolls each minute up after it ends, so the current minute is
          # never in the rollups.
          a_minute_back = now.utc.beginning_of_minute - 1.minute
          last_end = [a_minute_back, latest_end].compact.min

          return (last_end - kind[:default])..last_end if from.nil? && to.nil?

          raise InvalidWindowError unless from.is_a?(String) && to.is_a?(String)

          window_start = Time.iso8601(from).utc.beginning_of_minute
          window_end = Time.iso8601(to).utc.beginning_of_minute
          raise InvalidWindowError unless window_start < window_end

          # The page cannot know latest_end, so "the last 6 hours" ends at the
          # newest data, and a short overview starts earlier so pg_ash reads rollups.
          window_end = [window_end, last_end].min
          window_start = [window_start, window_end - kind[:allowed].begin].min
          oldest_start = [a_minute_back, newest_rollup].compact.min - MAX_LOOKBACK
          valid = kind[:allowed].cover?(window_end - window_start) && window_start >= oldest_start
          raise InvalidWindowError unless valid

          window_start..window_end
        rescue ArgumentError
          raise InvalidWindowError
        end

        # The end of pg_ash's minute rollups. pg_ash reads raw samples for any
        # window ending after it, so the overview must end by then; it lags
        # whenever the rollup cron job does.
        #
        # @return [Time, nil] nil before the first rollup
        def self.rollup_watermark(connection = ApplicationRecord.connection)
          new(nil, connection).rollup_watermark
        end

        # A report serves one request, because its read budget starts here.
        #
        # @param window [Range<Time>] from {.window}
        # @param connection [ActiveRecord::ConnectionAdapters::AbstractAdapter]
        def initialize(window, connection = ApplicationRecord.connection)
          @window = window
          @connection = connection
          @budget_ends_at = Gitlab::Metrics::System.monotonic_time + (READ_BUDGET_MS / 1000.0)
        end

        # @return [Hash] coverage: the period and source pg_ash actually read,
        #   which widens to whole hours when it falls back to hourly rollups;
        #   wait_event_types: load per wait event type, highest first;
        #   top_queries: the queries with the most load, see {#top_queries}
        def overview
          rows = read(<<~SQL.squish)
            SELECT key, source, period_start, period_end, avg_aas, peak_aas, p99_aas, pct
            FROM #{SCHEMA_NAME}.top(
              'wait_event_type',
              #{window_arguments},
              database => current_database(),
              n => #{WAIT_EVENT_TYPE_LIMIT}
            )
          SQL

          {
            coverage: coverage(rows.first),
            wait_event_types: rows.map { |row| { wait_event_type: row['key'], **aas_values(row, TOP_COLUMNS) } },
            top_queries: top_queries
          }
        end

        # @param wait_event_type [String] a wait event type from {#overview}
        # @return [Array<Hash>] the queries behind that load, highest first.
        #   query_id is nil for load that pg_ash could not attribute to a query.
        #   query_text comes from pg_stat_statements without values or comments,
        #   or is nil when pg_stat_statements has no text for it or the statement
        #   shows none.
        # @raise [QueryDetailsUnavailableError] when raw samples no longer cover
        #   the window
        def queries(wait_event_type:)
          rows = read(<<~SQL.squish)
            SELECT key, avg_aas, peak_aas, p99_aas, pct
            FROM #{SCHEMA_NAME}.top(
              'query_id',
              #{window_arguments},
              wait_event_type => #{connection.quote(wait_event_type)},
              database => current_database(),
              n => #{QUERY_LIMIT}
            )
          SQL

          query_rows(rows)
        rescue ActiveRecord::StatementInvalid => e
          raise QueryDetailsUnavailableError if e.message.include?(RAW_ATTRIBUTION_UNAVAILABLE)

          raise
        end

        # Every query in the window, whatever it waited on. The minute rollups
        # behind an overview window keep only each minute's top queries, so the
        # rest of the load comes back as one row with a nil query_id.
        #
        # @return [Array<Hash>] the queries with the most load, highest first
        def top_queries
          rows = read(<<~SQL.squish)
            SELECT key, avg_aas, peak_aas, p99_aas, pct
            FROM #{SCHEMA_NAME}.top(
              'query_id',
              #{window_arguments},
              database => current_database(),
              n => #{QUERY_LIMIT}
            )
          SQL

          query_rows(rows)
        end

        # Minutes keep spikes of a few minutes visible over a whole day.
        #
        # One statement reads every wait event type, so they all see the same rollups.
        # pg_ash picks minute or hourly rollups for each call, and separate reads could
        # pick differently when a rollup or cleanup runs between them.
        #
        # @param wait_event_types [Array<String>] wait event types from {#overview}
        # @return [Hash{String => Array<Hash>}] for each wait event type, in the order given,
        #   one row per minute, or per hour when the window starts before pg_ash's oldest
        #   minute rollup. The load values are nil for buckets without samples, and source
        #   names the pg_ash table read.
        def timelines(wait_event_types:)
          types = wait_event_types.map { |type| connection.quote(type) }.join(', ')

          rows = read(<<~SQL.squish)
            SELECT types.wait_event_type, timeline.bucket_start, timeline.source,
              timeline.avg_aas, timeline.peak_aas, timeline.p99_aas
            FROM unnest(ARRAY[#{types}]::text[]) WITH ORDINALITY AS types (wait_event_type, position)
            CROSS JOIN LATERAL #{SCHEMA_NAME}.timeline(
              #{window_arguments},
              bucket => interval '1 minute',
              wait_event_type => types.wait_event_type,
              database => current_database()
            ) AS timeline
            ORDER BY types.position, timeline.bucket_start
          SQL

          rows.each_with_object(wait_event_types.index_with { [] }) do |row, timelines|
            timelines[row['wait_event_type']] << {
              bucket_start: row['bucket_start'].utc.iso8601, source: row['source'], **aas_values(row, AAS_COLUMNS)
            }
          end
        end

        def rollup_watermark
          read(<<~SQL.squish).first&.fetch('watermark')
            SELECT #{SCHEMA_NAME}.ts_to_timestamptz(last_rollup_1m_ts) AS watermark
            FROM #{SCHEMA_NAME}.config
            WHERE singleton
          SQL
        end

        private

        attr_reader :window, :connection

        def window_arguments
          "since => #{quote_time(window.begin)}, until => #{quote_time(window.end)}"
        end

        def quote_time(time)
          "#{connection.quote(time.utc.iso8601)}::timestamptz"
        end

        def read(sql)
          Gitlab::Database::LoadBalancing::SessionMap.current(connection.load_balancer).use_primary do
            connection.transaction(requires_new: false) do
              PgAsh.execute(connection, format("SET LOCAL statement_timeout TO '%dms'", remaining_budget_ms))
              PgAsh.execute(connection, sql).to_a
            end
          end
        end

        # At least 1 ms, because a statement_timeout of 0 turns the timeout off.
        def remaining_budget_ms
          [((@budget_ends_at - Gitlab::Metrics::System.monotonic_time) * 1000).floor, 1].max
        end

        def coverage(row)
          return unless row

          { from: row['period_start'].utc.iso8601, to: row['period_end'].utc.iso8601, source: row['source'] }
        end

        def query_rows(rows)
          texts = query_texts(rows.filter_map { |row| row['key'] })

          rows.map do |row|
            { query_id: row['key'], query_text: texts[row['key']], **aas_values(row, TOP_COLUMNS) }
          end
        end

        # pg_ash returns only the first 100 characters of each query, so read
        # the full text from pg_stat_statements on the primary. pg_ash treats
        # pg_stat_statements as optional, so a failed read only drops the text,
        # and is tracked.
        #
        # @return [Hash{String => String}] query text without values or comments, by query ID
        def query_texts(query_ids)
          return {} if query_ids.empty?

          schema = read(<<~SQL.squish).first&.fetch('schema')
            SELECT namespace.nspname AS schema
            FROM pg_extension extension
            JOIN pg_namespace namespace ON namespace.oid = extension.extnamespace
            WHERE extension.extname = 'pg_stat_statements'
          SQL
          return {} unless schema

          ids = query_ids.map { |id| Integer(id, 10) }.join(',')
          rows = read(<<~SQL.squish)
            SELECT queryid::text AS query_id, query
            FROM #{connection.quote_column_name(schema)}.pg_stat_statements
            WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
              AND queryid = ANY(ARRAY[#{ids}]::bigint[])
          SQL

          rows.each_with_object({}) do |row, texts|
            text = QueryTextRedactor.redact(row['query'].to_s, limit: QUERY_TEXT_LIMIT)
            next unless text

            texts[row['query_id']] ||= text
          end
        rescue ActiveRecord::StatementInvalid => e
          Gitlab::ErrorTracking.track_exception(e)
          {}
        end

        # pg_ash leaves peak and p99 empty when the source it reads is coarser
        # than a minute, so every value can be nil.
        def aas_values(row, columns)
          columns.index_with { |column| row[column.to_s]&.to_f }
        end
      end
    end
  end
end
