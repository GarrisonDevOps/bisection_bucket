# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class SlackConfigService
        include Gitlab::Utils::StrongMemoize
        include AuthHeaders

        SERVER_KEY = :slack

        def initialize(current_user, namespace:, workflow:)
          @current_user = current_user
          @namespace = namespace
          @workflow = workflow
        end

        def execute
          return {} unless team_id && namespace && mcp_server && mcp_servers_user

          # Built first: it refreshes an expiring token, and the workspace check needs a live one.
          headers = build_mcp_server_headers(mcp_server, mcp_servers_user)
          return {} unless ::Ai::Catalog::McpServers::SlackHelper.token_in_workspace?(mcp_servers_user.token, team_id)

          # Trusted like GitLab MCP and Orbit, so DWS runs it without "Allow external MCP tools" until tools carry
          # an origin: https://gitlab.com/gitlab-org/gitlab/-/work_items/635112
          { SERVER_KEY => { URL: mcp_server.url, Headers: headers, Trusted: true } }
        end

        private

        attr_reader :current_user, :namespace, :workflow

        def team_id
          workflow&.messaging_callback_context&.dig('team_id')
        end

        def mcp_server
          ::Ai::Catalog::McpServers::SlackHelper.unblocked_gitlab_slack_app_server_for(current_user, namespace)
        end
        strong_memoize_attr :mcp_server

        def mcp_servers_user
          mcp_server.mcp_servers_users.find_by_user_id(current_user.id)
        end
        strong_memoize_attr :mcp_servers_user
      end
    end
  end
end
