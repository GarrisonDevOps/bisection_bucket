# frozen_string_literal: true

module Search
  module Zoekt
    class MetricsService
      include Gitlab::Loggable

      # The epoch, so a never-indexed node reads as an unbounded age and trips a staleness
      # alert instead of passing as fresh.
      NO_SUCCESSFUL_INDEX_RUN = 0

      METRICS = %i[
        enabled_namespaces_metrics
        indices_metrics
        node_metrics
        freshness_metrics
        expected_version_metrics
      ].freeze

      def self.execute(metric)
        instance = new(metric)

        instance.execute
      end

      def initialize(metric)
        @metric = metric.to_sym
      end

      def execute
        raise ArgumentError, "Unknown metric: #{metric.inspect}" unless METRICS.include?(metric)
        raise NotImplementedError unless respond_to?(metric, true)

        send(metric) # rubocop:disable GitlabSecurity/PublicSend -- We control the list of metrics in the source code
      end

      private

      attr_reader :metric

      def node_metrics
        ::Search::Zoekt::Node.for_search.online.find_each do |node|
          log_data = build_structured_payload(
            meta: node.metadata_json,
            enabled_namespaces_count: node.enabled_namespaces.count,
            indices_count: node.indices.count,
            indices_count_pending: node.indices.pending.count,
            task_count_pending: node.tasks.pending.count,
            task_count_failed: node.tasks.failed.count,
            task_count_processing_queue: node.tasks.processing_queue.count,
            task_count_orphaned: node.tasks.orphaned.count,
            task_count_done: node.tasks.done.count,
            message: 'Reporting metrics',
            metric: :node_metrics
          )

          logger.info(log_data)
        end
      end

      def indices_metrics
        log_data = build_structured_payload(
          'meta.zoekt.with_stale_used_storage_bytes_updated_at' => Index.with_stale_used_storage_bytes_updated_at.count,
          message: 'Reporting metrics',
          metric: :indices_metrics
        )

        logger.info(log_data)
      end

      def enabled_namespaces_metrics
        log_data = build_structured_payload(
          'meta.zoekt.enabled_namespaces_without_replicas' => EnabledNamespace.without_replicas.count,
          message: 'Reporting metrics',
          metric: :enabled_namespaces_metrics
        )

        logger.info(log_data)
      end

      # Cardinality is bounded by node count; deliberately not labeled per project or index.
      # Each Sidekiq process writes its own metrics file, so the merge mode - not the value set
      # here - decides what a scrape observes, and the two gauges need different modes.
      def freshness_metrics
        indexing_lag_gauge = ::Gitlab::Metrics.gauge(
          :search_zoekt_indexing_lag_seconds,
          'Age in seconds of the oldest Zoekt indexing task still waiting to be processed on a node'
        )

        last_indexed_at_gauge = ::Gitlab::Metrics.gauge(
          :search_zoekt_last_indexed_at_timestamp_seconds,
          'Unix timestamp of the most recently completed Zoekt indexing run on a node',
          {},
          :max
        )

        now = Time.current

        ::Search::Zoekt::Node.for_search.online.find_each do |node|
          labels = { zoekt_node_id: node.id, zoekt_node_name: node.metadata['name'] || 'unnamed' }

          indexing_lag = indexing_lag_seconds(node, now)
          last_indexed_at = last_indexed_at_timestamp(node)

          indexing_lag_gauge.set(labels, indexing_lag)
          last_indexed_at_gauge.set(labels, last_indexed_at)

          logger.info(build_structured_payload(
            'meta.zoekt.node_id' => node.id,
            'meta.zoekt.node_name' => node.metadata['name'] || 'unnamed',
            'meta.zoekt.indexing_lag_seconds' => indexing_lag,
            'meta.zoekt.last_indexed_at_timestamp_seconds' => last_indexed_at,
            message: 'Reporting metrics',
            metric: :freshness_metrics
          ))
        end
      end

      def expected_version_metrics
        ::Gitlab::Metrics.gauge(
          :search_zoekt_expected_version_info,
          'Zoekt version this GitLab release expects, from GITLAB_ZOEKT_VERSION',
          {},
          :max
        ).set({ version: Rails.root.join('GITLAB_ZOEKT_VERSION').read.chomp }, 1)
      end

      # Zero on a drained queue is a real value, not a missing one: it says indexing caught up.
      def indexing_lag_seconds(node, now)
        oldest_perform_at = node.tasks.processing_queue.oldest_perform_at
        return 0 if oldest_perform_at.nil?

        [now - oldest_perform_at, 0].max.round
      end

      # ever_indexed excludes indices still carrying the column default, so the intent is explicit
      # at the call site; it cannot change the exported value, because that default is the epoch and
      # the never-indexed sentinel is 0 too.
      def last_indexed_at_timestamp(node)
        newest_indexed_at = node.indices.ever_indexed.newest_last_indexed_at
        return NO_SUCCESSFUL_INDEX_RUN if newest_indexed_at.nil?

        newest_indexed_at.to_i
      end

      def logger
        @logger ||= ::Search::Zoekt::Logger.build
      end
    end
  end
end
