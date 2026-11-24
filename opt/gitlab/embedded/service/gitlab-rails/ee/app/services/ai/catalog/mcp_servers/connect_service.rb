# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class ConnectService
        def initialize(mcp_server:, redirect_uri:, return_to:)
          @mcp_server = mcp_server
          @redirect_uri = redirect_uri
          @return_to = return_to
        end

        def execute
          return error(_('This MCP server does not use OAuth authentication')) unless mcp_server.oauth?

          register_oauth_client if mcp_server.oauth_client_id.blank?

          pkce = registration_service.generate_pkce
          state = ::Gitlab::Oauth::ClientState.new(
            return_to: return_to,
            data: { mcp_server_id: mcp_server.id }
          )
          auth_server_metadata = registration_service.discover_metadata

          authorization_url = registration_service.build_authorization_url(
            authorization_endpoint: auth_server_metadata['authorization_endpoint'],
            client_id: mcp_server.oauth_client_id,
            redirect_uri: redirect_uri,
            state: state.encode,
            scope: requested_scope,
            code_challenge: pkce[:code_challenge],
            issuer: auth_server_metadata['issuer']
          )

          ServiceResponse.success(payload: { authorization_url: authorization_url,
                                             code_verifier: pkce[:code_verifier] })
        rescue StandardError => e
          error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))
        end

        private

        attr_reader :mcp_server, :redirect_uri, :return_to

        def requested_scope
          if ::Ai::Catalog::McpServers::SlackHelper.gitlab_slack_app_server?(mcp_server)
            return ::SlackIntegration::MCP_USER_SCOPES.join(' ')
          end

          registration_service.discover_resource_metadata&.fetch('scopes_supported', nil)&.join(' ')
        end

        def registration_service
          @registration_service ||= ::Gitlab::Oauth::DynamicRegistrationClient.new(
            server_url: mcp_server.url,
            client_name: "GitLab - #{mcp_server.name}",
            redirect_uris: [redirect_uri]
          )
        end

        def register_oauth_client
          result = registration_service.register_client

          mcp_server.update!(
            oauth_client_id: result[:client_id],
            oauth_client_secret: result[:client_secret]
          )
        rescue ::Gitlab::Oauth::DynamicRegistrationClient::ProtectedRegistrationError
          raise ::Gitlab::Oauth::DynamicRegistrationClient::ProtectedRegistrationError,
            _('This MCP server does not support dynamic client registration. ' \
              'Please configure the OAuth client ID for this server.')
        end

        def error(message)
          ServiceResponse.error(message: message)
        end
      end
    end
  end
end
