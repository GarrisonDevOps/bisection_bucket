# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class ConfigureSlackService
        HOMEPAGE_URL = 'https://docs.slack.dev/ai/slack-mcp-server'
        DESCRIPTION = 'Created by the GitLab for Slack app so GitLab Duo can read public Slack channels and ' \
          'threads. To update the client ID and client secret, change them in the GitLab for Slack app ' \
          'settings in the Admin area.'

        def initialize(organization:, current_user:, client_id:)
          @organization = organization
          @current_user = current_user
          @client_id = client_id
        end

        def execute
          mcp_server = ::Ai::Catalog::McpServer.in_organization(organization).find_by_url(SlackHelper::MCP_URL)
          return update(mcp_server) if mcp_server

          CreateService.new(
            organization: organization,
            current_user: current_user,
            params: {
              name: 'Slack',
              url: SlackHelper::MCP_URL,
              transport: :http,
              auth_type: :oauth,
              description: DESCRIPTION,
              homepage_url: HOMEPAGE_URL,
              oauth_client_id: client_id
            }
          ).execute
        end

        private

        attr_reader :organization, :current_user, :client_id

        def update(mcp_server)
          UpdateService.new(
            organization: organization,
            current_user: current_user,
            mcp_server: mcp_server,
            params: { oauth_client_id: client_id }
          ).execute
        end
      end
    end
  end
end
