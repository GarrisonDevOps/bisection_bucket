# frozen_string_literal: true

module Oauth
  class McpConnectorsAuthController < ApplicationController
    before_action :authenticate_user!
    rescue_from OAuth2::Error, with: :handle_oauth_error

    feature_category :ai_catalog_curation

    # Only these are echoed back, so a crafted link can't put its own text in the alert.
    # See RFC 6749 section 4.1.2.1. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
    AUTHORIZATION_ERROR_CODES = %w[
      access_denied invalid_request unauthorized_client unsupported_response_type invalid_scope server_error
      temporarily_unavailable
    ].freeze

    def connect
      mcp_server = find_mcp_server(mcp_server_params[:id])
      return render_404 unless mcp_server

      result = ::Ai::Catalog::McpServers::ConnectService.new(
        mcp_server: mcp_server,
        redirect_uri: oauth_mcp_connectors_callback_url,
        return_to: mcp_server_params[:return_to] || root_path
      ).execute

      if result.success?
        session[:"mcp_oauth_code_verifier_#{mcp_server.id}"] = result.payload[:code_verifier]
        redirect_to result.payload[:authorization_url], allow_other_host: true
      elsif return_to_path.present?
        redirect_to return_to_path, alert: result.message
      else
        redirect_back fallback_location: root_path, alert: result.message
      end
    end

    def disconnect
      mcp_server = ::Ai::Catalog::McpServer.find_by_id(mcp_server_params[:id])
      return render_404 unless mcp_server && can_disconnect?(mcp_server)

      result = ::Ai::Catalog::McpServers::RevokeTokenService.new(
        mcp_server: mcp_server,
        current_user: current_user
      ).execute

      if result.success?
        render json: {}, status: :ok
      else
        render json: { message: result.message }, status: :unprocessable_entity
      end
    end

    def callback
      state = ::Gitlab::Oauth::ClientState.from_state(mcp_server_params[:state])

      unless state.valid?
        redirect_to root_path, alert: _('OAuth state mismatch. Please try again.')
        return
      end

      mcp_server = find_mcp_server(state[:mcp_server_id])
      return render_404 unless mcp_server

      code_verifier = session.delete(:"mcp_oauth_code_verifier_#{mcp_server.id}")

      if mcp_server_params[:error]
        redirect_to state.return_to || root_path, alert: access_not_granted_message(mcp_server_params[:error])
        return
      end

      result = ::Ai::Catalog::McpServers::CallbackService.new(
        mcp_server: mcp_server,
        current_user: current_user,
        code: mcp_server_params[:code],
        redirect_uri: oauth_mcp_connectors_callback_url,
        code_verifier: code_verifier
      ).execute

      if result.success?
        redirect_to state.return_to || root_path, notice: _('Successfully connected to MCP server')
      else
        redirect_to state.return_to || root_path, alert: result.message
      end
    end

    private

    def mcp_server_params
      params.permit(:id, :return_to, :state, :code, :error)
    end

    def access_not_granted_message(error)
      return _('MCP server access was not granted.') unless AUTHORIZATION_ERROR_CODES.include?(error)

      format(_('MCP server access was not granted: %{error}'), error: error)
    end

    def return_to_path
      ::Gitlab::ReturnToLocation.new(mcp_server_params[:return_to]).full_path
    end

    def find_mcp_server(id)
      mcp_server = ::Ai::Catalog::McpServer.find_by_id(id)
      mcp_server if mcp_server && can?(current_user, :read_ai_catalog_mcp_server, mcp_server)
    end

    def can_disconnect?(mcp_server)
      mcp_server.connected_by_user?(current_user) || can?(current_user, :read_ai_catalog_mcp_server, mcp_server)
    end

    def handle_oauth_error
      redirect_to root_path, alert: _('OAuth error occurred. Please try again.')
    end
  end
end
