# frozen_string_literal: true

require_relative './publisher_sessions'

module Tasks
  module Gitlab
    module Geo
      module LogicalReplication
        # Gates subscription:drop, the point of no return before promotion: once the subscription is
        # gone, nothing shows whether the subscriber holds every published row. Rails-free like the
        # subscription tasks. An unreachable publisher blocks too, so a DR failover skips the check with
        # GEO_SKIP_REPLICATION_CHECK=1.
        class ReadinessCheck
          include PublisherSessions

          PublisherUnreachable = Class.new(StandardError)
          PublisherTimedOut = Class.new(StandardError)

          NON_BLOCKING_STATUSES = %i[ready slot_detached].freeze

          CONNECT_TIMEOUT_SECONDS = 5
          CONNECT_ATTEMPTS = 3
          CONNECT_RETRY_INTERVAL_SECONDS = 1
          STATEMENT_TIMEOUT_MS = 5_000
          # Shorter than the statement timeout, so a lock wait reports PG::LockNotAvailable rather than a timeout.
          LOCK_TIMEOUT_MS = 2_000
          CATCH_UP_TIMEOUT_SECONDS = 300
          POLL_INTERVAL_SECONDS = 1
          LIST_LIMIT = 20
          APPLICATION_NAME = 'geo-replication-readiness-check'
          KEEPALIVE_OPTIONS = { keepalives: 1, keepalives_idle: 5, keepalives_interval: 2, keepalives_count: 3 }.freeze

          Result = Struct.new(:status, :message, keyword_init: true) do
            def blocking?
              NON_BLOCKING_STATUSES.exclude?(status)
            end
          end

          SUBSCRIPTION_SQL = <<~SQL
            SELECT s.oid, s.subenabled, s.subslotname
            FROM pg_catalog.pg_subscription s
            JOIN pg_catalog.pg_database d ON d.oid = s.subdbid
            WHERE d.datname = current_database() AND s.subname = $1
          SQL

          # Cumulative since the subscription was created, so only an increase during the check counts.
          ERROR_COUNT_SQL = <<~SQL
            SELECT apply_error_count + sync_error_count AS error_count
            FROM pg_catalog.pg_stat_subscription_stats
            WHERE subid = $1
          SQL

          SUBSCRIBED_RELATIONS_SQL = <<~SQL
            SELECT n.nspname, c.relname, sr.srsubstate
            FROM pg_catalog.pg_subscription_rel sr
            JOIN pg_catalog.pg_class c ON c.oid = sr.srrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE sr.srsubid = $1
          SQL

          APPLY_WORKER_SQL = <<~SQL
            SELECT EXISTS (
              SELECT 1 FROM pg_catalog.pg_stat_subscription
              WHERE subid = $1 AND relid IS NULL AND leader_pid IS NULL AND pid IS NOT NULL
            ) AS running
          SQL

          PUBLISHER_TARGET_SQL = <<~SQL
            SELECT pg_catalog.pg_is_in_recovery() AS in_recovery,
                   (SELECT pubviaroot FROM pg_catalog.pg_publication WHERE pubname = $1) AS pubviaroot,
                   EXISTS (SELECT 1 FROM pg_catalog.pg_replication_slots WHERE slot_name = $2) AS slot_exists
          SQL

          PUBLISHED_RELATIONS_SQL = <<~SQL
            SELECT schemaname, tablename FROM pg_catalog.pg_publication_tables WHERE pubname = $1
          SQL

          CURRENT_LSN_SQL = 'SELECT pg_catalog.pg_current_wal_lsn() AS lsn'

          # confirmed_flush_lsn also advances while the publisher is idle, from the subscriber's
          # replies to keepalives, so it reaches a WAL position recorded after writes stopped.
          SLOT_PROGRESS_SQL = <<~SQL
            SELECT confirmed_flush_lsn >= $2::pg_lsn AS caught_up,
                   pg_catalog.pg_wal_lsn_diff($2::pg_lsn, confirmed_flush_lsn) AS lag_bytes
            FROM pg_catalog.pg_replication_slots
            WHERE slot_name = $1
          SQL

          def initialize( # rubocop:disable Metrics/ParameterLists -- keywords with defaults, callers pass only what they change
            subscriber:, publisher_connection_string:, publication_name:, subscription_name:,
            catch_up_timeout: CATCH_UP_TIMEOUT_SECONDS, poll_interval: POLL_INTERVAL_SECONDS,
            connect_attempts: CONNECT_ATTEMPTS, connect_retry_interval: CONNECT_RETRY_INTERVAL_SECONDS,
            block_on_writers: false
          )
            @subscriber = subscriber
            @publisher_connection_string = publisher_connection_string
            @publication_name = publication_name
            @subscription_name = subscription_name
            @catch_up_timeout = catch_up_timeout
            @poll_interval = poll_interval
            @connect_attempts = connect_attempts
            @connect_retry_interval = connect_retry_interval
            @block_on_writers = block_on_writers
          end

          # Errors from the subscriber, and from a publisher that answers with an error, are raised:
          # nothing was verified, so the caller must not treat them as a pass.
          def execute
            subscription = subscriber.exec_params(SUBSCRIPTION_SQL, [subscription_name]).first
            return no_subscription_result unless subscription
            # Usually a retry after a failed DROP: subscription:drop detaches the slot right before it
            return slot_detached_result if subscription['subslotname'].blank?
            return not_configured_result if publisher_connection_string.blank?
            return subscription_disabled_result unless pg_true?(subscription['subenabled'])

            @subscription_id = subscription['oid']
            @slot_name = subscription['subslotname']

            publisher = connect_with_retries
            check_against(publisher)
          rescue PublisherUnreachable => e
            unreachable_result(e.cause || e)
          rescue PublisherTimedOut => e
            timed_out_result(e.cause)
          ensure
            publisher&.close
          end

          private

          attr_reader :subscriber, :publisher_connection_string, :publication_name, :subscription_name,
            :catch_up_timeout, :poll_interval, :connect_attempts, :connect_retry_interval,
            :subscription_id, :slot_name

          def check_against(publisher)
            errors_before = error_count
            target = publisher_query(publisher, PUBLISHER_TARGET_SQL, [publication_name, slot_name]).first

            wrong_target = wrong_target_reason(target)
            return wrong_target_result(wrong_target) if wrong_target

            via_partition_root = pg_true?(target['pubviaroot'])

            uncovered = published_relations(publisher) - subscribed_relations.keys
            return uncovered_relations_result(uncovered, via_partition_root: via_partition_root) if uncovered.any?

            lagging = wait_for_catch_up_without_writers(publisher, errors_before)
            return lagging if lagging

            not_ready = subscribed_relations.reject { |_relation, state| state == 'r' }.keys
            return relations_not_ready_result(not_ready) if not_ready.any?

            ready_result(via_partition_root: via_partition_root)
          end

          def wrong_target_reason(target)
            if pg_true?(target['in_recovery'])
              'it is in recovery, so it is a standby rather than the publisher'
            elsif target['pubviaroot'].nil?
              "it has no publication named #{publication_name}"
            elsif !pg_true?(target['slot_exists'])
              missing_slot_reason
            end
          end

          def missing_slot_reason
            "it has no replication slot named #{slot_name}"
          end

          # A commit that finishes between the writer checks leaves no session behind and can land past
          # the first wait's target, so the subscriber catches up once more after the last check.
          def wait_for_catch_up_without_writers(publisher, errors_before)
            return wait_for_catch_up(publisher, errors_before) unless block_on_writers?

            writers_result(publisher) ||
              wait_for_catch_up(publisher, errors_before) ||
              writers_result(publisher) ||
              wait_for_catch_up(publisher, errors_before)
          end

          # Returns nil once the slot has confirmed the publisher's WAL position from the start of the
          # wait, or a blocking Result.
          def wait_for_catch_up(publisher, errors_before)
            target_lsn = publisher_query(publisher, CURRENT_LSN_SQL).first['lsn']
            deadline = monotonic_now + catch_up_timeout

            loop do
              return apply_errors_result if error_count > errors_before

              progress = publisher_query(publisher, SLOT_PROGRESS_SQL, [slot_name, target_lsn]).first
              return wrong_target_result(missing_slot_reason) unless progress
              return if pg_true?(progress['caught_up'])
              return lagging_result(progress['lag_bytes']) if monotonic_now >= deadline

              sleep poll_interval
            end
          end

          def connect_with_retries
            attempts = 0

            begin
              connection = PG.connect(
                publisher_connection_string,
                connect_timeout: CONNECT_TIMEOUT_SECONDS, application_name: APPLICATION_NAME, **KEEPALIVE_OPTIONS
              )
              # Session settings, not SET LOCAL in a transaction: this connection stays open while it
              # polls, and an idle-in-transaction session would trip the publisher write activity check.
              connection.exec("SET statement_timeout = #{STATEMENT_TIMEOUT_MS}; SET lock_timeout = #{LOCK_TIMEOUT_MS}")
              connection
            rescue PG::ConnectionBad, PG::UnableToSend
              connection&.close
              # Otherwise a PG.connect failing on the next attempt would close it again and raise
              connection = nil
              attempts += 1
              raise PublisherUnreachable if attempts >= connect_attempts

              sleep connect_retry_interval
              retry
            end
          end

          def publisher_query(publisher, sql, params = [])
            publisher.exec_params(sql, params)
          rescue PG::ConnectionBad, PG::UnableToSend
            raise PublisherUnreachable
          rescue PG::QueryCanceled
            # Unlike an outage, a slow publisher is still up, so the unverified check must block
            raise PublisherTimedOut
          end

          # Only subscription:drop asks: the catch-up target is the end of the replicated rows only once
          # writes have stopped.
          def writers_result(publisher)
            masked = publisher_query(publisher, MASKED_SESSIONS_SQL).first['masked_sessions'].to_i
            return stats_not_visible_result(publisher.user) if masked > 0

            writers = publisher_query(publisher, SESSIONS_SQL).to_a.select { |row| blocking_session?(row) }
            writes_detected_result(writers) if writers.any?
          end

          def block_on_writers?
            @block_on_writers
          end

          def published_relations(publisher)
            publisher_query(publisher, PUBLISHED_RELATIONS_SQL, [publication_name]).values.map { |row| row.join('.') }
          end

          def subscribed_relations
            subscriber.exec_params(SUBSCRIBED_RELATIONS_SQL, [subscription_id]).values
              .to_h { |schema, table, state| ["#{schema}.#{table}", state] }
          end

          def error_count
            subscriber.exec_params(ERROR_COUNT_SQL, [subscription_id]).first&.dig('error_count').to_i
          end

          def apply_worker_running?
            pg_true?(subscriber.exec_params(APPLY_WORKER_SQL, [subscription_id]).first['running'])
          end

          # A plain libpq connection returns booleans as 't' and 'f', and an ActiveRecord raw connection
          # as true and false.
          def pg_true?(value)
            value == true || value == 't'
          end

          def monotonic_now
            Process.clock_gettime(Process::CLOCK_MONOTONIC)
          end

          def ready_result(via_partition_root:)
            message = "Subscription #{subscription_name} is ready to drop: every published relation is " \
              "replicated, and the subscriber has caught up with the publisher."
            message += "\n#{not_via_partition_root_warning}" unless via_partition_root

            Result.new(status: :ready, message: message)
          end

          def slot_detached_result
            Result.new(status: :slot_detached, message: <<~MSG.squish)
              Subscription #{subscription_name} has no replication slot, so the replication cannot be
              checked. subscription:drop detaches it after this check passes, but so does a drop with
              GEO_SKIP_REPLICATION_CHECK=1 or a manual ALTER SUBSCRIPTION ... SET (slot_name = NONE).
              Dropping the subscription also removes its slot on the publisher.
            MSG
          end

          def no_subscription_result
            Result.new(status: :no_subscription, message: "Subscription #{subscription_name} does not exist.")
          end

          def subscription_disabled_result
            Result.new(status: :subscription_disabled, message: <<~MSG.squish)
              Subscription #{subscription_name} is disabled, so the subscriber cannot catch up with the
              publisher. Enable it with subscription:enable, then retry.
            MSG
          end

          def not_configured_result
            Result.new(status: :not_configured, message: <<~MSG.squish)
              GEO_PUBLISHER_CONNECTION_STRING is not set, so the subscriber cannot be compared with the
              publisher. Set it, or set GEO_SKIP_REPLICATION_CHECK=1 to skip the check.
            MSG
          end

          def unreachable_result(error)
            Result.new(status: :unreachable, message: <<~MSG.squish)
              Could not connect to the publisher (#{error.class}: #{error.message.strip}), so nothing was
              verified. Check GEO_PUBLISHER_CONNECTION_STRING and that the publisher is up, then retry.
            MSG
          end

          def timed_out_result(error)
            Result.new(status: :publisher_timed_out, message: <<~MSG.squish)
              The publisher accepted the connection but did not answer within #{STATEMENT_TIMEOUT_MS}ms
              (#{error.class}), so nothing was verified. Retry once it answers.
            MSG
          end

          def wrong_target_result(reason)
            Result.new(status: :wrong_target, message: <<~MSG.squish)
              GEO_PUBLISHER_CONNECTION_STRING does not look like the publisher: #{reason}.
            MSG
          end

          def writes_detected_result(sessions)
            Result.new(status: :writes_detected, message: <<~MSG.squish)
              Write activity on the publisher: #{sessions.map { |row| session_description(row) }.join('; ')}.
              Stop writes on the publisher (maintenance mode on, Puma and Sidekiq stopped), then retry.
            MSG
          end

          def stats_not_visible_result(role)
            Result.new(status: :stats_not_visible, message: <<~MSG.squish)
              Role #{role} cannot see other sessions in pg_stat_activity, so the check cannot tell whether
              the publisher still takes writes. Grant it the stats role: GRANT pg_read_all_stats TO #{role};
            MSG
          end

          def uncovered_relations_result(relations, via_partition_root:)
            message = <<~MSG.squish
              #{relations.size} published relation(s) are not in subscription #{subscription_name}, so
              their rows are not replicated: #{relation_list(relations)}. Run subscription:refresh, wait
              for the copy to finish, then retry.
            MSG

            unless via_partition_root
              message += " Create any of them missing on the subscriber first, owned by the tables' owner."
            end

            Result.new(status: :uncovered_relations, message: message)
          end

          def relations_not_ready_result(relations)
            Result.new(status: :relations_not_ready, message: <<~MSG.squish)
              #{relations.size} relation(s) have not finished their initial copy: #{relation_list(relations)}.
              Wait until pg_subscription_rel reports srsubstate = 'r' for each, then retry.
            MSG
          end

          def apply_errors_result
            Result.new(status: :apply_errors, message: <<~MSG.squish)
              Subscription #{subscription_name} reported replication errors during the check, for example
              a partition missing on the subscriber. Check the subscriber's PostgreSQL log, fix the cause,
              then retry.
            MSG
          end

          def lagging_result(lag_bytes)
            behind = "The subscriber did not catch up with the publisher within #{catch_up_timeout}s " \
              "(#{lag_bytes} bytes behind)"

            if apply_worker_running?
              Result.new(
                status: :lagging,
                message: "#{behind}. Stop writes on the publisher, then retry, or allow more time with " \
                  "GEO_REPLICATION_CHECK_TIMEOUT."
              )
            else
              Result.new(
                status: :apply_worker_down,
                message: "#{behind}, and subscription #{subscription_name} has no apply worker running. " \
                  "Check the subscriber's PostgreSQL log."
              )
            end
          end

          def not_via_partition_root_warning
            "Warning: publication #{publication_name} was created without publish_via_partition_root, so " \
              "rows written to a partition created after the last subscription:refresh are not replicated."
          end

          def relation_list(relations)
            list = relations.sort.first(LIST_LIMIT).join(', ')
            relations.size > LIST_LIMIT ? "#{list}, and #{relations.size - LIST_LIMIT} more" : list
          end
        end
      end
    end
  end
end
