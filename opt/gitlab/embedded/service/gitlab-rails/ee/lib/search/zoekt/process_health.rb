# frozen_string_literal: true

module Search
  module Zoekt
    module ProcessHealth
      MIN_VERSION = '1.16.0'
      MMAP_UNHEALTHY = 0.95

      PROCESSES = %w[indexer webserver].freeze

      class << self
        # @return [Boolean] true if all online nodes meet MIN_VERSION
        def active?
          Node.all_at_least_version?(MIN_VERSION)
        end

        # @param node [Search::Zoekt::Node]
        # @return [Boolean] true if the node should be excluded from search
        #   routing because of crashloop, mmap exhaustion, or webserver staleness.
        def unhealthy?(node)
          return false unless active?
          return true if webserver_stale?(node)

          PROCESSES.any? do |process|
            metrics = process_metrics(node, process)
            next false if metrics.blank?

            restart_count_exceeded?(metrics) || mmap_exhausted?(metrics)
          end
        end

        private

        def process_metrics(node, process)
          node.metadata.dig('process_health', process)
        end

        def restart_count_exceeded?(metrics)
          metrics['restarts_15m'].to_i > Settings.max_restarts_15m
        end

        def mmap_exhausted?(metrics)
          mmap_ratio(metrics) >= MMAP_UNHEALTHY
        end

        def mmap_ratio(metrics)
          current = metrics['mmap_current'].to_i
          max = metrics['mmap_max'].to_i
          return 0.0 if max <= 0

          current.to_f / max
        end

        def webserver_stale?(node)
          return true if node.webserver_last_seen_at.nil?

          node.webserver_last_seen_at < Node::ONLINE_DURATION_THRESHOLD.ago
        end
      end
    end
  end
end
