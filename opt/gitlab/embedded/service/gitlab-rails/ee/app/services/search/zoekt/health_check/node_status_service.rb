# frozen_string_literal: true

module Search
  module Zoekt
    module HealthCheck
      class NodeStatusService
        include ActionView::Helpers::DateHelper
        include StatusReporting

        def self.execute(...)
          new(...).execute
        end

        def initialize(logger:)
          @logger = logger
          @status = :healthy
          @warnings = []
          @errors = []
        end

        def execute
          logger.info("")
          logger.info(Rainbow("Node Status:").bright.yellow)

          check_nodes_online
          check_offline_nodes
          check_storage_utilization

          {
            status: @status,
            warnings: @warnings,
            errors: @errors
          }
        end

        private

        def check_nodes_online
          total_count = Search::Zoekt::Node.for_search.count
          online_count = Search::Zoekt::Node.for_search.online.count

          if total_count == 0
            add_error("Configure and deploy Zoekt nodes to enable exact code search")
            log_check("✗ No nodes configured", :red)
            return
          end

          if online_count == 0
            add_error("Check Zoekt node connectivity and restart offline services")
            log_check("✗ #{total_count} of #{total_count} nodes offline", :red)
          elsif online_count < total_count
            offline_count = total_count - online_count
            add_warning("Investigate #{offline_count} offline nodes and restore connectivity")
            log_check("⚠ #{online_count} of #{total_count} nodes online", :yellow)
          else
            log_check("✓ #{online_count} of #{total_count} nodes online", :green)
          end
        end

        def check_offline_nodes
          offline_nodes = Search::Zoekt::Node.for_search.offline
          return if offline_nodes.empty?

          longest_offline = offline_nodes.minimum(:last_seen_at)
          if longest_offline
            duration = time_ago_in_words(longest_offline)
            log_check("⚠ WARNING: Nodes offline (last seen: #{longest_offline.utc} - #{duration} ago)", :yellow)
          else
            log_check("⚠ WARNING: Offline nodes with unknown last seen time", :yellow)
          end
        end

        def check_storage_utilization
          online_nodes = Search::Zoekt::Node.for_search.online
          return if online_nodes.empty?

          critical_nodes = online_nodes.select(&:watermark_exceeded_critical?)
          high_nodes = online_nodes.select(&:watermark_exceeded_high?)

          if critical_nodes.any?
            add_error("Add nodes or clean up storage on #{critical_nodes.count} nodes with critical usage")
            log_check("✗ Critical storage usage on #{critical_nodes.count} nodes", :red)
          elsif high_nodes.any?
            add_warning(
              "Monitor and consider adding nodes or expanding storage on #{high_nodes.count} nodes with high usage"
            )
            log_check("⚠ High storage usage on #{high_nodes.count} nodes", :yellow)
          else
            # Calculate average storage usage manually since storage_percent_used is a method
            total_usage = online_nodes.sum(&:storage_percent_used)
            avg_usage = (total_usage / online_nodes.count).round(4)
            log_check("✓ Storage usage healthy (avg: #{(avg_usage * 100).round(1)}%)", :green)
          end
        end
      end
    end
  end
end
