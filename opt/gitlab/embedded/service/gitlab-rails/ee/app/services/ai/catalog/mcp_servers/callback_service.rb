# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class CallbackService
        def initialize(mcp_server:, current_user:, code:, redirect_uri:, code_verifier: nil)
          @mcp_server = mcp_server
          @current_user = current_user
          @code = code
          @redirect_uri = redirect_uri
          @code_verifier = code_verifier
        end

        def execute
          token_params = { redirect_uri: redirect_uri }
          token_params[:code_verifier] = code_verifier if code_verifier

          access_token = build_oauth_client.auth_code.get_token(code, **token_params)

          store_token(access_token)
        rescue OAuth2::Error, StandardError => e
          error(format(_('Failed to connect to MCP server: %{error}'), error: e.message))
        end

        private

        attr_reader :mcp_server, :current_user, :code, :redirect_uri, :code_verifier

        def registration_service
          @registration_service ||= ::Gitlab::Oauth::DynamicRegistrationClient.new(
            server_url: mcp_server.url,
            client_name: "GitLab - #{mcp_server.name}",
            redirect_uris: [redirect_uri]
          )
        end

        def build_oauth_client
          auth_server_url = registration_service.discover_auth_server_url
          metadata = registration_service.discover_metadata(auth_server_url)

          OAuth2::Client.new(
            mcp_server.oauth_client_id,
            mcp_server.resolved_oauth_client_secret,
            site: auth_server_url,
            authorize_url: metadata['authorization_endpoint'],
            token_url: metadata['token_endpoint'],
            auth_scheme: ::Gitlab::Oauth::DynamicRegistrationClient.token_endpoint_auth_scheme(metadata)
          )
        end

        def store_token(access_token)
          mcp_server_user = mcp_server.mcp_servers_users.find_by_user_id(current_user.id)
          expires_at = access_token.expires_at ? Time.zone.at(access_token.expires_at) : nil
          attributes = { token: access_token.token, refresh_token: access_token.refresh_token, expires_at: expires_at }

          saved = if mcp_server_user
                    mcp_server_user.update(attributes)
                  else
                    create_attrs = attributes.merge(
                      user_id: current_user.id, organization_id: mcp_server.organization_id
                    )
                    mcp_server.mcp_servers_users.create(create_attrs).persisted?
                  end

          return error(_('Failed to store token')) unless saved

          audit_token_stored
          ServiceResponse.success
        end

        def audit_token_stored
          audit_context = {
            name: 'mcp_server_oauth_token_stored',
            author: current_user,
            scope: current_user,
            target: current_user,
            target_details: current_user.name,
            message: "Connected to MCP server: #{mcp_server.name}",
            additional_details: {
              mcp_server_id: mcp_server.id,
              mcp_server_name: mcp_server.name
            }
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, mcp_server_id: mcp_server.id)
        end

        def error(message)
          ServiceResponse.error(message: message)
        end
      end
    end
  end
end
