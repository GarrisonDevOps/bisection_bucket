# frozen_string_literal: true

module EE
  module Profiles
    module ChatNamesController
      extend ::Gitlab::Utils::Override

      private

      override :after_create_path
      def after_create_path(chat_name)
        mcp_server = slack_mcp_server_to_connect(chat_name)
        return super unless mcp_server

        oauth_mcp_connectors_connect_path(id: mcp_server.id, return_to: super)
      end

      # Unlinking Slack should stop GitLab Duo reading Slack as the user, so the token goes too.
      override :after_destroy
      def after_destroy(chat_name)
        return unless slack_app_account?(chat_name.team_id, chat_name.chat_id)

        mcp_server = ::Ai::Catalog::McpServers::SlackHelper.gitlab_slack_app_server(::Current.organization)
        return unless mcp_server&.connected_by_user?(current_user)

        ::Ai::Catalog::McpServers::RevokeTokenService.new(mcp_server: mcp_server, current_user: current_user).execute
      end

      def slack_mcp_server_to_connect(chat_name)
        return unless chat_name.persisted? && slack_app_params?

        mcp_server = ::Ai::Catalog::McpServers::SlackHelper.gitlab_slack_app_server_for(current_user,
          ::Current.organization)
        return unless mcp_server

        mcp_server unless ::Ai::Catalog::McpServers::SlackHelper
          .connected_in_workspace?(current_user, mcp_server, chat_name.team_id)
      end
    end
  end
end
