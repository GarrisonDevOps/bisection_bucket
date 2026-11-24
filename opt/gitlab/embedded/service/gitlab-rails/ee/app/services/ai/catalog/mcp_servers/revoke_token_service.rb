# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class RevokeTokenService
        def initialize(mcp_server:, current_user:)
          @mcp_server = mcp_server
          @current_user = current_user
        end

        def execute
          mcp_server_user = mcp_server.mcp_servers_users.find_by_user_id(current_user.id)

          return error(_('No connection found for this MCP server')) unless mcp_server_user

          revoke_token_at_provider(mcp_server_user)

          return error(_('Failed to disconnect from MCP server')) unless mcp_server_user.destroy

          ServiceResponse.success
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

        def revoke_token_at_provider(mcp_server_user)
          metadata = registration_service.discover_metadata
          revocation_endpoint = metadata['revocation_endpoint']

          return unless revocation_endpoint.present?

          credentials = Base64.strict_encode64(
            "#{mcp_server.oauth_client_id}:#{mcp_server.resolved_oauth_client_secret}"
          )

          Gitlab::HTTP.post(
            revocation_endpoint,
            body: URI.encode_www_form(token: mcp_server_user.token),
            headers: {
              'Content-Type' => 'application/x-www-form-urlencoded',
              'Authorization' => "Basic #{credentials}"
            },
            timeout: ::Gitlab::Oauth::DynamicRegistrationClient::REQUEST_TIMEOUT
          )
        rescue StandardError => e
          # Provider revocation failures are logged but do not block local disconnect
          Gitlab::AppLogger.warn(
            message: 'Failed to revoke MCP server token at provider',
            mcp_server_id: mcp_server.id,
            error: e.message
          )
        end

        def error(message)
          ServiceResponse.error(message: message)
        end
      end
    end
  end
end
