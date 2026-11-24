# frozen_string_literal: true

module Search
  module Zoekt
    module HealthCheck
      class ConnectivityService
        include StatusReporting

        HEALTH_CHECK_QUERY = 'zoekt_health_check'

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
          logger.info(Rainbow("Connectivity:").bright.yellow)

          check_jwt_token_generation
          check_node_connectivity

          {
            status: @status,
            warnings: @warnings,
            errors: @errors
          }
        end

        private

        def check_jwt_token_generation
          token = ::Search::Zoekt::JwtAuth.authorization_header
          if token.present?
            log_check("✓ JWT token generation successful", :green)
          else
            add_error("Configure JWT secret for Zoekt authentication")
            log_check("✗ JWT token generation failed", :red)
          end
        rescue StandardError => e
          add_error("Fix JWT configuration - #{e.message}")
          log_check("✗ JWT token generation error", :red)
        end

        def check_node_connectivity
          online_nodes = Search::Zoekt::Node.for_search.online.to_a
          return if online_nodes.empty?

          successful_connections = 0
          total_response_time = 0

          online_nodes.each do |node|
            start_time = Time.current
            result = test_node_connection(node)
            response_time = ((Time.current - start_time) * 1000).round
            total_response_time += response_time

            if result[:success]
              successful_connections += 1
              log_check("✓ Node #{node.id} (#{node_name(node)}) - #{response_time}ms response", :green)
            elsif result[:error]
              # Specific error with exception details
              add_warning("Verify node #{node.id} is accessible and resolve network issues")
              log_check(
                "✗ Node #{node.id} (#{node_name(node)}) - #{result[:error].class.name}: #{result[:error].message}",
                :red
              )
            else
              # Connection failure
              add_warning("Check network connectivity and node status for node #{node.id}")
              log_check("⚠ Node #{node.id} (#{node_name(node)}) - connection failed", :yellow)
            end
          end

          # Overall connectivity assessment
          if successful_connections == online_nodes.count
            avg_response_time = (total_response_time / successful_connections.to_f).round
            log_check("✓ All #{online_nodes.count} online nodes reachable (avg: #{avg_response_time}ms)", :green)
          elsif successful_connections > 0
            add_warning("Investigate connectivity issues with #{online_nodes.count - successful_connections} nodes")
            log_check("⚠ #{successful_connections}/#{online_nodes.count} nodes reachable", :yellow)
          else
            add_error("Restore network connectivity to all Zoekt nodes")
            log_check("✗ No nodes reachable", :red)
          end
        end

        def test_node_connection(node)
          # Test connectivity using the existing Zoekt client with a simple search

          client = ::Gitlab::Search::Zoekt::Client.instance
          # Use a minimal project ID for connectivity testing
          project_id = Project.first&.id || 1
          client.search(
            HEALTH_CHECK_QUERY,
            num: 1,
            project_ids: [project_id],
            node_id: node.id,
            search_mode: :exact,
            source: 'health_check'
          )
          { success: true }
        rescue ::Search::Zoekt::Errors::ClientConnectionError
          { success: false, error: nil } # Connection failed
        rescue StandardError => e
          # Any other exception indicates a problem (invalid search params, etc.)
          { success: false, error: e }
        end
      end
    end
  end
end
