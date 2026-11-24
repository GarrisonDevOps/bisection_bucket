# frozen_string_literal: true

module Search
  module Zoekt
    module HealthCheck
      class ProcessHealthService
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
          logger.info(Rainbow('Process Health:').bright.yellow)

          nodes = ::Search::Zoekt::Node.for_search.online.to_a

          if nodes.empty?
            log_check('- No online nodes to check process health', :white)
            return { status: @status, warnings: @warnings, errors: @errors }
          end

          nodes.each { |node| check_node_process_health(node) }

          { status: @status, warnings: @warnings, errors: @errors }
        end

        private

        def check_node_process_health(node)
          process_health = node.metadata['process_health']

          if process_health.blank?
            log_check("- Node #{node.id} (#{node_name(node)}): N/A", :white)
            return
          end

          check_indexer_health(node, process_health['indexer'])
          check_webserver_health(node, process_health['webserver'], node.webserver_last_seen_at)
        end

        def check_indexer_health(node, indexer)
          if indexer.blank?
            log_check("Node #{node.id} (#{node_name(node)}) Indexer: N/A", :white)
            return
          end

          restarts_15m = indexer['restarts_15m'].to_i
          mmap_current = indexer['mmap_current'].to_i
          mmap_max = indexer['mmap_max'].to_i

          if restarts_15m >= 2
            add_error("Node #{node.id} indexer is crashlooping (restarts_15m: #{restarts_15m})")
            msg = "✗ Node #{node.id} (#{node_name(node)}) Indexer: crashlooping (restarts_15m: #{restarts_15m})"
            log_check(msg, :red)
          elsif mmap_usage_critical?(mmap_current, mmap_max)
            mmap_pct = mmap_percentage(mmap_current, mmap_max)
            add_error("Node #{node.id} indexer mmap usage critical (#{mmap_pct}%)")
            log_check("✗ Node #{node.id} (#{node_name(node)}) Indexer: mmap critical (#{mmap_pct}%)", :red)
          elsif restarts_15m == 1
            add_warning("Node #{node.id} indexer had a recent restart (restarts_15m: #{restarts_15m})")
            msg = "⚠ Node #{node.id} (#{node_name(node)}) Indexer: recent restart (restarts_15m: #{restarts_15m})"
            log_check(msg, :yellow)
          elsif mmap_usage_warning?(mmap_current, mmap_max)
            mmap_pct = mmap_percentage(mmap_current, mmap_max)
            add_warning("Node #{node.id} indexer mmap usage high (#{mmap_pct}%)")
            log_check("⚠ Node #{node.id} (#{node_name(node)}) Indexer: mmap high (#{mmap_pct}%)", :yellow)
          else
            log_check("✓ Node #{node.id} (#{node_name(node)}) Indexer: healthy", :green)
          end
        end

        def check_webserver_health(node, webserver, webserver_last_seen_at)
          if webserver_offline?(webserver_last_seen_at)
            add_error("Node #{node.id} webserver is offline")
            log_check("✗ Node #{node.id} (#{node_name(node)}) Webserver: offline", :red)
            return
          end

          if webserver.blank?
            log_check("Node #{node.id} (#{node_name(node)}) Webserver: N/A", :white)
            return
          end

          restarts_15m = webserver['restarts_15m'].to_i
          mmap_current = webserver['mmap_current'].to_i
          mmap_max = webserver['mmap_max'].to_i

          if restarts_15m >= 2
            add_error("Node #{node.id} webserver is crashlooping (restarts_15m: #{restarts_15m})")
            msg = "✗ Node #{node.id} (#{node_name(node)}) Webserver: crashlooping (restarts_15m: #{restarts_15m})"
            log_check(msg, :red)
          elsif mmap_usage_critical?(mmap_current, mmap_max)
            mmap_pct = mmap_percentage(mmap_current, mmap_max)
            add_error("Node #{node.id} webserver mmap usage critical (#{mmap_pct}%)")
            log_check("✗ Node #{node.id} (#{node_name(node)}) Webserver: mmap critical (#{mmap_pct}%)", :red)
          elsif restarts_15m == 1
            add_warning("Node #{node.id} webserver had a recent restart (restarts_15m: #{restarts_15m})")
            msg = "⚠ Node #{node.id} (#{node_name(node)}) Webserver: recent restart (restarts_15m: #{restarts_15m})"
            log_check(msg, :yellow)
          elsif mmap_usage_warning?(mmap_current, mmap_max)
            mmap_pct = mmap_percentage(mmap_current, mmap_max)
            add_warning("Node #{node.id} webserver mmap usage high (#{mmap_pct}%)")
            log_check("⚠ Node #{node.id} (#{node_name(node)}) Webserver: mmap high (#{mmap_pct}%)", :yellow)
          else
            log_check("✓ Node #{node.id} (#{node_name(node)}) Webserver: healthy", :green)
          end
        end

        def webserver_offline?(webserver_last_seen_at)
          return false if webserver_last_seen_at.nil?

          webserver_last_seen_at < ::Search::Zoekt::Node::ONLINE_DURATION_THRESHOLD.ago
        end

        def mmap_usage_critical?(mmap_current, mmap_max)
          ::Search::Zoekt::Node.mmap_usage_level(mmap_current, mmap_max) == :critical
        end

        def mmap_usage_warning?(mmap_current, mmap_max)
          ::Search::Zoekt::Node.mmap_usage_level(mmap_current, mmap_max) == :warning
        end

        def mmap_percentage(mmap_current, mmap_max)
          return 0 if mmap_max == 0

          ((mmap_current.to_f / mmap_max) * 100).round(1)
        end
      end
    end
  end
end
