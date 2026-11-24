# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class RefreshTokenService
        def initialize(mcp_server:, current_user:)
          @mcp_server = mcp_server
          @current_user = current_user
        end

        def execute
          mcp_server_user = mcp_server.mcp_servers_users.find_by_user_id(current_user.id)

          return error(_('No token found for this MCP server')) unless mcp_server_user
          return error(_('No refresh token available')) if mcp_server_user.refresh_token.blank?

          new_token = build_oauth_token(mcp_server_user).refresh!

          saved = mcp_server_user.update(
            token: new_token.token,
            refresh_token: new_token.refresh_token.presence || mcp_server_user.refresh_token,
            expires_at: new_token.expires_at ? Time.zone.at(new_token.expires_at) : nil
          )

          return error(_('Failed to store refreshed token')) unless saved

          ServiceResponse.success(payload: { token: new_token.token })
        rescue OAuth2::Error => e
          error(format(_('Failed to refresh token: %{error}'), error: e.message))
        end

        private

        attr_reader :mcp_server, :current_user

        def registration_service
          @registration_service ||= ::Gitlab::Oauth::DynamicRegistrationClient.new(
            server_url: mcp_server.url,
            client_name: "GitLab - #{mcp_server.name}",
            redirect_uris: []
          )
        end

        def build_oauth_token(mcp_server_user)
          auth_server_url = registration_service.discover_auth_server_url
          metadata = registration_service.discover_metadata(auth_server_url)

          client = OAuth2::Client.new(
            mcp_server.oauth_client_id,
            mcp_server.resolved_oauth_client_secret,
            site: auth_server_url,
            authorize_url: metadata['authorization_endpoint'],
            token_url: metadata['token_endpoint'],
            auth_scheme: ::Gitlab::Oauth::DynamicRegistrationClient.token_endpoint_auth_scheme(metadata)
          )

          OAuth2::AccessToken.new(
            client,
            mcp_server_user.token,
            refresh_token: mcp_server_user.refresh_token
          )
        end

        def error(message)
          ServiceResponse.error(message: message)
        end
      end
    end
  end
end
