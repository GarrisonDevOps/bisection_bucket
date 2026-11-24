# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      # Builds the headers that authenticate the current user to an MCP server.
      #
      # Including classes must define `current_user`, the user who owns `mcp_servers_user`,
      # because an expiring OAuth token is refreshed on their behalf.
      module AuthHeaders
        CLOCK_SKEW = 2.minutes
        private_constant :CLOCK_SKEW

        private

        def build_mcp_server_headers(server, mcp_servers_user)
          return {} unless mcp_servers_user

          case server.auth_type
          when 'oauth'
            refresh_token_if_expired(server, mcp_servers_user)
            { Authorization: "Bearer #{mcp_servers_user.token}" }
          else
            {}
          end
        end

        def refresh_token_if_expired(server, mcp_servers_user)
          return unless mcp_servers_user.expires_at
          return unless mcp_servers_user.expires_at <= Time.current + CLOCK_SKEW

          ::Ai::Catalog::McpServers::RefreshTokenService.new(
            mcp_server: server,
            current_user: current_user
          ).execute

          mcp_servers_user.reset
        end
      end
    end
  end
end
