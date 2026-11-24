# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      module SlackHelper
        extend self

        MCP_URL = 'https://mcp.slack.com/mcp'
        # Runs before every Slack session starts, so a slow Slack must not hold it up for long.
        AUTH_TEST_TIMEOUT = 5.seconds

        # Keep in sync with `pre_approved_tools` in the ai-assist `slack_assistant` flow config.
        PRE_APPROVED_TOOLS = %w[
          slack_slack_search_public
          slack_slack_search_channels
          slack_slack_read_channel
          slack_slack_read_thread
        ].freeze

        def gitlab_slack_app_server(organization)
          slack_app_id = Gitlab::CurrentSettings.slack_app_id
          return if slack_app_id.blank?

          ::Ai::Catalog::McpServer.in_organization(organization).find_by_url_and_oauth_client_xid(MCP_URL, slack_app_id)
        end

        # The flag is checked here too because users who can read the catalog pass the policy without it.
        def gitlab_slack_app_server_for(user, organization)
          return unless ::Feature.enabled?(:slack_duo_mcp_server, user)

          mcp_server = gitlab_slack_app_server(organization)
          mcp_server if mcp_server && Ability.allowed?(user, :read_ai_catalog_mcp_server, mcp_server)
        end

        def unblocked_gitlab_slack_app_server_for(user, namespace)
          mcp_server = gitlab_slack_app_server_for(user, namespace.organization)
          mcp_server unless mcp_server && blocked_in?(mcp_server, namespace)
        end

        def slack_flow?(flow_reference)
          flow_reference == ::Ai::Catalog::FoundationalFlow.slack_assistant_v1.foundational_flow_reference
        end

        # The server itself, and whether the namespace blocked it, are checked separately.
        def session_gets_slack_server?(user, flow_reference)
          slack_flow?(flow_reference) &&
            ::Feature.enabled?(:slack_duo_mcp_server, user) &&
            ::Feature.enabled?(:mcp_client, user)
        end

        def gitlab_slack_app_server?(mcp_server)
          slack_app_id = Gitlab::CurrentSettings.slack_app_id

          slack_app_id.present? && mcp_server.url == MCP_URL && mcp_server.oauth_client_id == slack_app_id
        end

        # A user has one Slack token, issued for one workspace. Used from another workspace, it would
        # read the token's workspace and post the results where the session runs.
        # Slack::API logs when Slack rejects the token or can't be reached.
        def token_in_workspace?(token, team_id)
          return false if team_id.blank?

          token_team_id = ::Slack::API.new(user_token: token).auth_test(timeout: AUTH_TEST_TIMEOUT)['team_id']
          return true if token_team_id == team_id

          if token_team_id
            ::Gitlab::IntegrationsLogger.info(
              message: 'Slack token belongs to another Slack workspace',
              slack_workspace_id: team_id,
              token_slack_workspace_id: token_team_id
            )
          end

          false
        end

        def connected_in_workspace?(user, mcp_server, team_id)
          mcp_servers_user = mcp_server.mcp_servers_users.find_by_user_id(user.id)

          mcp_servers_user.present? && token_in_workspace?(mcp_servers_user.token, team_id)
        end

        private

        def blocked_in?(mcp_server, namespace)
          return false unless ::Feature.enabled?(:mcp_server_block_enforcement, namespace.root_ancestor)

          ::Ai::Catalog::McpServerBlock.blocked_server_ids_for(namespace, [mcp_server.id]).exists?
        end
      end
    end
  end
end
