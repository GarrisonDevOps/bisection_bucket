# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Fans out one SyncNamespaceSessionCreditsWorker job per root namespace that
    # CustomersDot billed for Duo Agent Platform sessions inside the sync window.
    # Self-managed has one instance-level subscription and gets a single job.
    class SyncSessionCreditsCronWorker
      include ApplicationWorker
      include ClickHouseWorker
      include ::CronjobQueue

      idempotent!
      deduplicate :until_executed
      data_consistency :sticky
      feature_category :value_stream_management
      urgency :low
      tags :clickhouse
      defer_on_database_health_signal :gitlab_main_org, [:namespaces]

      SPREAD_MINUTES = 330
      GROUP_LOAD_BATCH_SIZE = 1_000
      LOOKUP_WINDOW = 90.days
      LOOKUP_MAX_RUNTIME = 4.minutes

      # hasNextPage true with no endCursor: following it would skip pages for good.
      MalformedResponseError = Class.new(StandardError)
      LookupOverTimeError = Class.new(StandardError)

      def perform
        return unless ::Gitlab::ClickHouse.globally_enabled_for_analytics?

        @enumerated = 0
        @enqueued = 0

        log_extra_metadata_on_done(:namespace_jobs_buffered, buffered_namespace_jobs)

        stop_reason = saas? ? sync_root_namespaces : enqueue_instance

        log_extra_metadata_on_done(:namespaces_enumerated, @enumerated)
        log_extra_metadata_on_done(:namespaces_enqueued, @enqueued)
        log_extra_metadata_on_done(:stop_reason, stop_reason)
      end

      private

      def sync_root_namespaces
        ids = root_namespace_ids
        return :cdot_error unless ids

        @enumerated = ids.size
        groups = root_namespaces(ids)
        observe_freshness(groups)
        enqueue_root_namespaces(groups)

        @lookup_over_time ? :over_time : :completed
      end

      def root_namespaces(namespace_ids)
        namespace_ids.each_slice(GROUP_LOAD_BATCH_SIZE).flat_map do |ids|
          ::Group.id_in(ids).with_route.to_a
        end
      end

      def observe_freshness(groups)
        stats = SessionCredits::SyncFreshness.observe(groups.map(&:id))

        stats&.each { |key, value| log_extra_metadata_on_done(key, value) }
      end

      def enqueue_root_namespaces(groups)
        in_buckets(groups).each do |minute, bucket|
          if minute == 0
            SyncNamespaceSessionCreditsWorker.bulk_perform_async_with_contexts(bucket, **context_procs)
          else
            SyncNamespaceSessionCreditsWorker.bulk_perform_in_with_contexts(minute.minutes, bucket, **context_procs)
          end
        end

        @enqueued = groups.size
      end

      # Round-robin, so every minute of the spread is used however many groups there are.
      def in_buckets(groups)
        buckets = [groups.size, SPREAD_MINUTES].min

        groups.group_by.with_index { |_, index| index % buckets }
      end

      def context_procs
        {
          arguments_proc: ->(group) { group.id },
          context_proc: ->(group) { { namespace: group } }
        }
      end

      def buffered_namespace_jobs
        ::Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService
          .queue_size(SyncNamespaceSessionCreditsWorker.name)
      end

      def enqueue_instance
        @enumerated = 1

        SyncNamespaceSessionCreditsWorker.perform_async(nil)
        @enqueued = 1

        :completed
      end

      def root_namespace_ids
        client = ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new
        limiter = ::Gitlab::Metrics::RuntimeLimiter.new(LOOKUP_MAX_RUNTIME)
        updated_after = LOOKUP_WINDOW.ago
        ids = Set.new
        after = nil

        loop do
          page = client.get_session_namespaces(updated_after: updated_after, after: after)
          ids += page[:namespaces].map do |node|
            node[:rootNamespaceId].to_i
          end

          after = next_token(page[:page_info])
          break unless after

          next unless limiter.over_time?

          @lookup_over_time = true
          fail_cdot_lookup(:over_time,
            LookupOverTimeError.new("Stopped after #{LOOKUP_MAX_RUNTIME.inspect} with more pages left"))
          break
        end

        ids.to_a.select(&:positive?)
      rescue ::Gitlab::SubscriptionPortal::SubscriptionUsageClient::ResponseError => e
        fail_cdot_lookup(e.reason || :response_error, e)
      rescue *::Gitlab::HTTP::HTTP_ERRORS => e
        fail_cdot_lookup(:connection_error, e)
      rescue MalformedResponseError => e
        fail_cdot_lookup(:malformed_response, e)
      end

      def next_token(page_info)
        return unless page_info.is_a?(Hash) && page_info[:hasNextPage] == true

        page_info[:endCursor].presence || raise(MalformedResponseError, 'hasNextPage without an endCursor')
      end

      def fail_cdot_lookup(reason, error)
        # The client already reports its own ResponseError.
        unless error.is_a?(::Gitlab::SubscriptionPortal::SubscriptionUsageClient::ResponseError)
          ::Gitlab::ErrorTracking.track_exception(error, reason: reason.to_s)
        end

        ::Gitlab::Metrics.counter(
          :duo_workflow_session_credits_v2_fetch_failures_total,
          'Total failed v2 CustomersDot session syncs'
        ).increment(reason: "namespace_lookup_#{reason}")

        ::Gitlab::AppLogger.warn(
          Labkit::Fields::CLASS_NAME => self.class.name,
          Labkit::Fields::LOG_MESSAGE => 'Failed to list session namespaces from CustomersDot',
          Labkit::Fields::ERROR_TYPE => reason.to_s,
          Labkit::Fields::ERROR_MESSAGE => error.message
        )

        nil
      end

      def saas?
        ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end
    end
  end
end
