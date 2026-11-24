# frozen_string_literal: true

module Ai
  module Catalog
    class McpServerPolicy < ::BasePolicy
      delegate { @subject.organization }

      # The GitLab for Slack app's server must stay readable without `Ai::Catalog.mcp_servers_available?`.
      overrides :read_ai_catalog_mcp_server

      condition(:readable_in_organization) do
        can?(:read_ai_catalog_mcp_server, @subject.organization)
      end

      condition(:gitlab_slack_app_server, scope: :subject) do
        ::Ai::Catalog::McpServers::SlackHelper.gitlab_slack_app_server?(@subject)
      end

      condition(:organization_user) do
        @subject.organization.user?(@user)
      end

      condition(:slack_duo_mcp_server_enabled, scope: :user) do
        ::Feature.enabled?(:slack_duo_mcp_server, @user)
      end

      rule { readable_in_organization }.enable :read_ai_catalog_mcp_server

      rule { gitlab_slack_app_server & slack_duo_mcp_server_enabled & organization_user }.policy do
        enable :read_ai_catalog_mcp_server
      end
    end
  end
end
