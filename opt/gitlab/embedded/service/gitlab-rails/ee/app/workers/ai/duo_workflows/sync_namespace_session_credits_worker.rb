# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Pulls the sessions CustomersDot changed since this root namespace's cursor and
    # upserts their credit totals into ClickHouse. One job per root namespace, or one
    # instance-level job on self-managed.
    class SyncNamespaceSessionCreditsWorker
      include ApplicationWorker
      include ClickHouseWorker

      data_consistency :delayed
      idempotent!
      deduplicate :until_executed
      feature_category :value_stream_management
      urgency :throttled
      tags :clickhouse
      loggable_arguments 0

      concurrency_limit -> { 20 }

      CustomersDotConnectionError = Class.new(StandardError)
      MalformedResponseError = Class.new(StandardError)
      SyncFailure = Class.new(StandardError)
      RateLimitWaitTooLong = Class.new(StandardError)

      MAX_RUNTIME = 2.minutes
      SELF_MANAGED_MAX_RUNTIME = 4.minutes
      ROWS_THRESHOLD_FOR_INSERT = 10_000
      RATE_LIMIT_WAIT = 5.seconds
      # Not degradations, so not measured by the SLI
      SLI_UNMEASURED_REASONS = %w[undefined_field no_cdot_subscription_found no_billable_license].freeze

      def perform(root_namespace_id = nil)
        return unless ::Gitlab::ClickHouse.globally_enabled_for_analytics?

        @root_namespace_id = root_namespace_id
        @stats = {
          pages_fetched: 0, rows_written: 0, calls_made: 0, rate_limit_waits: 0, failure_reason: '', cdot_synced_at: ''
        }
        @stop_reason = :error

        @stop_reason = sync
      rescue ::Sidekiq::Shutdown
        @stop_reason = :interrupted
        raise
      ensure
        if @stats
          record_sli
          log_done
        end
      end

      private

      attr_reader :root_namespace_id

      def sync
        return fail_with(:missing_root_namespace) if saas? && root_namespace_id.nil?
        return fail_with(:no_billable_license) unless client

        @cursor_before = cursor.value_us
        after = cursor.after_token
        @cursor_reseeded = cursor.reseeded?

        page_through(after)
      rescue RateLimitWaitTooLong
        @stats[:failure_reason] = 'rate_limited'
        count_failure(:rate_limited)
        :rate_limited
      rescue ::Gitlab::SubscriptionPortal::SubscriptionUsageClient::ResponseError => e
        fail_with(e.reason || :response_error, e)
      rescue CustomersDotConnectionError => e
        fail_with(:connection_error, e)
      rescue MalformedResponseError => e
        fail_with(:malformed_response, e)
      rescue ::ClickHouse::Client::DatabaseError, *::Gitlab::HTTP::HTTP_ERRORS => e
        fail_with(:clickhouse_error, e)
      rescue ::Redis::BaseError, ::RedisClient::Error => e
        fail_with(:redis_error, e)
      ensure
        flush_pending
      end

      def page_through(after)
        limiter = ::Gitlab::Metrics::RuntimeLimiter.new(saas? ? MAX_RUNTIME : SELF_MANAGED_MAX_RUNTIME)
        @buffer = []
        @after = after

        loop do
          page = fetch_page(@after, limiter)
          @after = next_token(page[:page_info])
          @buffer.concat(Array(page[:sessions]))
          next if @after && @buffer.size < ROWS_THRESHOLD_FOR_INSERT && !limiter.over_time?

          failure = flush_buffer
          return fail_with(failure) if failure

          return finish_window unless @after
          return :over_time if limiter.over_time?
        end
      end

      def fetch_page(after, limiter)
        @stats[:calls_made] += 1
        page = client.get_sessions(updated_after: cursor.updated_after, after: after)
        @stats[:pages_fetched] += 1
        @stats[:cdot_synced_at] = page[:synced_at].to_s

        page
      rescue ::Gitlab::SubscriptionPortal::SubscriptionUsageClient::ResponseError => e
        raise unless e.reason == :rate_limited

        wait = e.retry_after || RATE_LIMIT_WAIT.to_i
        raise RateLimitWaitTooLong if wait >= limiter.max_runtime - limiter.elapsed_time

        @stats[:rate_limit_waits] += 1
        sleep(wait)
        retry
      rescue *::Gitlab::HTTP::HTTP_ERRORS => e
        raise CustomersDotConnectionError, "#{e.class}: #{e.message}"
      end

      def next_token(page_info)
        return unless page_info.is_a?(Hash) && page_info[:hasNextPage] == true

        page_info[:endCursor].presence || raise(MalformedResponseError, 'hasNextPage without an endCursor')
      end

      def flush_buffer
        return if @buffer.blank?

        pending = @buffer
        @buffer = []
        failure = write(pending)
        return failure if failure

        cursor.advance!(@max_updated_at_us)
        cursor.store_after_token(@after) if @after

        nil
      end

      def write(nodes)
        response = SessionCredits::IngestService.new(nodes: nodes).execute
        return response.reason if response.error?

        @stats[:rows_written] += response.payload[:rows_written]
        @max_updated_at_us = [@max_updated_at_us, response.payload[:max_updated_at_us]].compact.max

        nil
      end

      def finish_window
        cursor.clear_after_token
        SessionCredits::SyncFreshness.record_completion(root_namespace_id)

        :completed
      end

      def flush_pending
        failure = flush_buffer
        fail_with(failure) if failure
      rescue ::ClickHouse::Client::DatabaseError, *::Gitlab::HTTP::HTTP_ERRORS => e
        fail_with(:clickhouse_error, e)
      rescue ::Redis::BaseError, ::RedisClient::Error => e
        fail_with(:redis_error, e)
      end

      def fail_with(reason, error = nil)
        @stats[:failure_reason] = reason.to_s if @stats[:failure_reason].empty?

        SessionCredits::SyncFreshness.record_completion(root_namespace_id) if reason == :no_cdot_subscription_found

        # The client already reports its own ResponseError; everything else is ours.
        unless error.is_a?(::Gitlab::SubscriptionPortal::SubscriptionUsageClient::ResponseError)
          ::Gitlab::ErrorTracking.track_exception(
            error || SyncFailure.new(reason.to_s), root_namespace_id: root_namespace_id, reason: reason.to_s
          )
        end

        count_failure(reason)

        ::Gitlab::AppLogger.warn(
          Labkit::Fields::CLASS_NAME => self.class.name,
          Labkit::Fields::LOG_MESSAGE => 'Failed to sync session credits',
          Labkit::Fields::GL_ROOT_NAMESPACE_ID => root_namespace_id,
          Labkit::Fields::ERROR_TYPE => reason.to_s,
          Labkit::Fields::ERROR_MESSAGE => error&.message
        )

        :error
      end

      def count_failure(reason)
        ::Gitlab::Metrics.counter(
          :duo_workflow_session_credits_v2_fetch_failures_total,
          'Total failed v2 CustomersDot session syncs'
        ).increment(reason: reason.to_s)
      end

      def record_sli
        return if @stop_reason.in?(%i[interrupted rate_limited])
        return if SLI_UNMEASURED_REASONS.include?(@stats[:failure_reason])

        ::Gitlab::Metrics::DuoWorkflowSessionCreditsSyncSlis.record(error: !@stop_reason.in?(%i[completed over_time]))
      end

      def log_done
        @stats.each { |key, value| log_extra_metadata_on_done(key, value) }
        log_extra_metadata_on_done(:root_namespace_id, root_namespace_id)
        log_extra_metadata_on_done(:cursor_before, @cursor_before.to_i)
        log_extra_metadata_on_done(:cursor_after, @cursor_before ? cursor.value_us : 0)
        log_extra_metadata_on_done(:cursor_lag_s, cursor_lag_s)
        log_extra_metadata_on_done(:cursor_reseeded, @cursor_reseeded == true)
        log_extra_metadata_on_done(:cdot_sync_lag_s, cdot_sync_lag_s)
        log_extra_metadata_on_done(:stop_reason, @stop_reason)
      end

      def cursor_lag_s
        return 0 unless @cursor_before

        [Time.current.to_i - cursor.position_time.to_i, 0].max
      end

      def cdot_sync_lag_s
        synced_at = Time.iso8601(@stats[:cdot_synced_at])

        [Time.current.to_i - synced_at.to_i, 0].max
      rescue ArgumentError
        0
      end

      def cursor
        @cursor ||= SessionCredits::Cursor.new(root_namespace_id)
      end

      def client
        return @client if defined?(@client)

        @client =
          if saas?
            ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new(namespace_id: root_namespace_id)
          else
            license_key = ::License.billable_license&.data
            license_key && ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new(license_key: license_key)
          end
      end

      def saas?
        ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end
    end
  end
end
