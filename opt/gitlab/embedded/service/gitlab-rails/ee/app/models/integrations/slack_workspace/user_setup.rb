# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # Whether a Slack user still has to connect Slack's MCP server before GitLab Duo runs for them.
    class UserSetup
      include Gitlab::Utils::StrongMemoize

      def initialize(user:, namespace:, flow_reference:)
        @user = user
        @namespace = namespace
        @flow_reference = flow_reference
      end

      # :unavailable when the session wouldn't get the Slack MCP server anyway, so nobody is blocked
      # on a connection that can't be used.
      def slack_context
        return :unavailable unless slack_helper.session_gets_slack_server?(user, flow_reference) && mcp_server

        mcp_server.connected_by_user?(user) ? :connected : :not_connected
      end
      strong_memoize_attr :slack_context

      # No return_to: Slack's link formatter doesn't accept the `%` of an encoded path, so the link wouldn't render.
      def connect_url
        ::Gitlab::Routing.url_helpers.oauth_mcp_connectors_connect_url(id: mcp_server.id)
      end

      private

      attr_reader :user, :namespace, :flow_reference

      def slack_helper
        ::Ai::Catalog::McpServers::SlackHelper
      end

      def mcp_server
        slack_helper.unblocked_gitlab_slack_app_server_for(user, namespace)
      end
      strong_memoize_attr :mcp_server
    end
  end
end
