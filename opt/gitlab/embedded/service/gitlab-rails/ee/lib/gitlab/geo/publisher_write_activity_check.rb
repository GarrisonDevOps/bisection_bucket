# frozen_string_literal: true

module Gitlab
  module Geo
    # Gates LR promotion on the publisher taking no writes: the sequence sync and the zero-lag
    # cutover are only correct if nothing writes to the publisher in that window. A DR failover
    # must never be blocked, so it aborts only on evidence from a publisher it actually reached.
    class PublisherWriteActivityCheck
      include Gitlab::Utils::Executable
      include ::Tasks::Gitlab::Geo::LogicalReplication::PublisherSessions

      Error = Class.new(StandardError)

      CONNECT_TIMEOUT_SECONDS = 5
      STATEMENT_TIMEOUT_MS = 5_000
      CONNECT_ATTEMPTS = 3
      CONNECT_RETRY_INTERVAL_SECONDS = 1
      APPLICATION_NAME = 'geo-write-activity-check'

      # statement_timeout is enforced server-side, so a socket that black-holes after connect
      # would otherwise wait forever. Keepalives give up on a dead peer in about 11 seconds.
      KEEPALIVE_OPTIONS = { keepalives: 1, keepalives_idle: 5, keepalives_interval: 2, keepalives_count: 3 }.freeze

      # Only these let a promotion continue. Everything else means a writer was seen, or the
      # publisher answered but the check could not prove anything about it.
      NON_BLOCKING_STATUSES = %i[no_writes unreachable].freeze

      Result = Struct.new(:status, :sessions, :maintenance_mode, :message, :error, keyword_init: true) do
        def blocking?
          NON_BLOCKING_STATUSES.exclude?(status)
        end
      end

      TARGET_SQL = <<~SQL
        SELECT pg_catalog.pg_is_in_recovery() AS in_recovery,
               EXISTS (SELECT 1 FROM pg_catalog.pg_publication WHERE pubname = $1) AS publication_exists
      SQL

      MAINTENANCE_MODE_SQL = 'SELECT maintenance_mode FROM application_settings ORDER BY id DESC LIMIT 1'

      def initialize(
        connection_string: ENV['GEO_PUBLISHER_CONNECTION_STRING'],
        publication_name: ENV.fetch('GEO_PUBLICATION', 'geo_publication'),
        connect_timeout: CONNECT_TIMEOUT_SECONDS,
        statement_timeout_ms: STATEMENT_TIMEOUT_MS,
        connect_attempts: CONNECT_ATTEMPTS,
        connect_retry_interval: CONNECT_RETRY_INTERVAL_SECONDS
      )
        @connection_string = connection_string
        @publication_name = publication_name
        @connect_timeout = connect_timeout
        @statement_timeout_ms = statement_timeout_ms
        @connect_attempts = connect_attempts
        @connect_retry_interval = connect_retry_interval
      end

      def execute
        return log_and_return(not_configured_result) if connection_string.blank?

        connection = nil
        connection = connect_with_retries

        log_and_return(run_checks(connection))
      rescue StandardError => e
        # Only the connect phase raises this far: run_checks classifies its own errors.
        Gitlab::ErrorTracking.track_exception(e) unless e.is_a?(PG::Error)
        log_and_return(unreachable_result(e))
      ensure
        rollback_quietly(connection)
        connection&.close
      end

      private

      attr_reader :connection_string, :publication_name, :connect_timeout, :statement_timeout_ms,
        :connect_attempts, :connect_retry_interval

      # A transient blip must not silently skip the gate: an unreachable publisher degrades to
      # a warning, so give the connection a few chances before concluding that.
      def connect_with_retries
        attempts = 0

        begin
          PG.connect(
            connection_string,
            connect_timeout: connect_timeout, application_name: APPLICATION_NAME, **KEEPALIVE_OPTIONS
          )
        rescue PG::ConnectionBad
          attempts += 1
          raise unless attempts < connect_attempts

          sleep connect_retry_interval
          retry
        end
      end

      def run_checks(connection)
        connection.exec('BEGIN')
        # A wedged publisher must not stall a promotion. SET LOCAL inside one transaction,
        # because a plain session SET is dropped by a transaction-pooling proxy.
        connection.exec("SET LOCAL statement_timeout = #{Integer(statement_timeout_ms)}")

        wrong_target_result_for(connection) ||
          (stats_not_visible_result(connection) if masked_sessions?(connection)) ||
          sessions_result(connection)
      rescue PG::QueryCanceled => e
        # The statement timeout fired: the publisher accepts connections but cannot answer,
        # which is what a dying publisher looks like mid-failover. Not blocking.
        timed_out_result(e)
      rescue PG::ServerError => e
        # The publisher answered with an error, so it is reachable and nothing was verified.
        check_failed_result(e)
      rescue PG::Error => e
        unreachable_result(e)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        check_failed_result(e)
      end

      # A nil publication_name skips the publication half only; in_recovery is always enforced.
      # It exists so the integration spec can run against a database that has no publication.
      def wrong_target_result_for(connection)
        row = connection.exec_params(TARGET_SQL, [publication_name.to_s]).first

        if row['in_recovery'] == 't'
          return wrong_target_result('it is in recovery, so it is a standby rather than the publisher')
        end

        return if publication_name.nil? || row['publication_exists'] == 't'

        wrong_target_result("it has no publication named #{publication_name}")
      end

      def masked_sessions?(connection)
        connection.exec(MASKED_SESSIONS_SQL).first['masked_sessions'].to_i > 0
      end

      def sessions_result(connection)
        sessions = connection.exec(SESSIONS_SQL).to_a
        blocking_sessions = sessions.select { |row| blocking_session?(row) }
        maintenance_mode = read_maintenance_mode(connection)
        status = blocking_sessions.any? ? :writes_detected : :no_writes

        Result.new(
          status: status,
          sessions: sessions,
          maintenance_mode: maintenance_mode,
          message: sessions_message(status, sessions, blocking_sessions, maintenance_mode)
        )
      end

      def read_maintenance_mode(connection)
        connection.exec(MAINTENANCE_MODE_SQL).first&.dig('maintenance_mode')
      rescue PG::Error
        nil
      end

      # Everything here is read-only, so an unconditional rollback is correct. It also clears
      # an aborted transaction left behind by a failed maintenance_mode read.
      def rollback_quietly(connection)
        connection&.exec('ROLLBACK')
      rescue PG::Error
        nil
      end

      def not_configured_result
        Result.new(status: :not_configured, sessions: [], message: <<~MSG.squish)
          GEO_PUBLISHER_CONNECTION_STRING is not set, so the publisher write activity check
          cannot run. Set it to the publisher connection string the subscription uses, or set
          GEO_SKIP_WRITE_ACTIVITY_CHECK=1 to promote without the check.
        MSG
      end

      def unreachable_result(error)
        Result.new(
          status: :unreachable,
          sessions: [],
          error: error,
          message: "Could not reach the publisher (#{error.class}: #{error.message.strip}), " \
            "skipping the write activity check."
        )
      end

      def timed_out_result(error)
        Result.new(status: :unreachable, sessions: [], error: error, message: <<~MSG.squish)
          The publisher accepted the connection but did not answer within
          #{Integer(statement_timeout_ms)}ms (#{error.class}), so it is treated as unreachable.
          Skipping the write activity check.
        MSG
      end

      def check_failed_result(error)
        Result.new(status: :check_failed, sessions: [], error: error, message: <<~MSG.squish)
          The publisher is reachable but the write activity check failed
          (#{error.class}: #{error.message.strip}), so nothing was verified. Blocking promotion.
        MSG
      end

      def wrong_target_result(reason)
        Result.new(status: :wrong_target, sessions: [], message: <<~MSG.squish)
          GEO_PUBLISHER_CONNECTION_STRING does not look like the publisher: #{reason}.
          Blocking promotion.
        MSG
      end

      def stats_not_visible_result(connection)
        Result.new(
          status: :stats_not_visible,
          sessions: [],
          message: "Role #{connection.user} cannot see other sessions in pg_stat_activity, so the write activity " \
            "check cannot tell whether the publisher is safe to promote from. Grant it the stats role:\n  " \
            "GRANT pg_read_all_stats TO #{connection.user};"
        )
      end

      def sessions_message(status, sessions, blocking_sessions, maintenance_mode)
        header =
          if status == :writes_detected
            "Write activity detected on the publisher, blocking promotion: " \
              "#{blocking_sessions.map { |row| session_description(row) }.join('; ')}."
          elsif sessions.any?
            "No writes detected on the publisher. #{sessions.size} read session(s) reported: " \
              "#{sessions.map { |row| session_description(row) }.join('; ')}."
          else
            "No writes detected on the publisher. No client sessions reported."
          end

        message = "#{header} Maintenance mode: #{maintenance_mode_description(maintenance_mode)}."
        return message unless status == :no_writes && maintenance_mode == 'f'

        "#{message} Maintenance mode is off on the publisher, so writes can resume at any moment."
      end

      def maintenance_mode_description(maintenance_mode)
        case maintenance_mode
        when 't' then 'enabled'
        when 'f' then 'disabled'
        else 'unknown'
        end
      end

      def log_and_return(result)
        payload = {
          message: 'Publisher write activity check completed',
          status: result.status,
          session_count: result.sessions.size,
          maintenance_mode: result.maintenance_mode
        }

        if result.status == :writes_detected
          blocking = result.sessions.select { |row| blocking_session?(row) }
          payload[:blocking_pids] = blocking.map { |row| Integer(row['pid']) }
        end

        if result.error
          payload[:error_class] = result.error.class.name
          payload[:error_message] = result.error.message
        end

        case result.status
        when :no_writes then Gitlab::Geo::Logger.info(payload)
        when :unreachable then Gitlab::Geo::Logger.warn(payload)
        else Gitlab::Geo::Logger.error(payload)
        end

        result
      end
    end
  end
end
