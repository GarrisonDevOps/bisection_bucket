# frozen_string_literal: true

module API
  module Helpers
    module Mcp
      # Shared JSON-RPC helpers used by both MCP API endpoints.
      module JsonRpc
        # Methods under this prefix are JSON-RPC notifications, which carry no id and get no response.
        # See: https://modelcontextprotocol.io/specification/2025-06-18/basic#notifications
        NOTIFICATION_METHOD_PREFIX = 'notifications/'

        module Constants
          JSONRPC_VERSION = '2.0'

          # See: https://www.jsonrpc.org/specification#error_object
          # Parse error -32700 is not listed because Workhorse answers 400 before it reaches Rails.
          JSONRPC_ERRORS = {
            invalid_request: { code: -32600, message: 'Invalid Request' },
            method_not_found: { code: -32601, message: 'Method not found' },
            invalid_params: { code: -32602, message: 'Invalid params' },
            internal_error: { code: -32603, message: 'Internal error' },
            # Defined by MCP revision 2026-07-28.
            unsupported_protocol_version: { code: -32022, message: 'Unsupported protocol version' }
          }.freeze
        end

        include Constants

        # Echoing the id lets a caller match this response to its request.
        # The JSON-RPC spec only allows a string, a whole number, or null for the id,
        # so anything else (an object, a float, a boolean) comes back as null.
        # See: https://www.jsonrpc.org/specification#response_object
        def jsonrpc_request_id
          id = params[:id]

          id if id.is_a?(Integer) || id.is_a?(String)
        end

        def jsonrpc_notification?
          params[:method].to_s.start_with?(NOTIFICATION_METHOD_PREFIX)
        end

        # Rejects a request without an id unless it is a notification. A present id is validated by the
        # endpoint's Grape `id` declaration. `key?` is used because `params[:id]` is nil both when the id is
        # absent and when the client sent `"id": null`.
        def reject_missing_jsonrpc_request_id!
          return if params.key?(:id) || jsonrpc_notification?

          render_invalid_jsonrpc_request!(['id is missing'])
        end

        # Validates the per-request `_meta` of MCP revision 2026-07-28. `initialize` and notifications are skipped.
        # A legacy request, or any request while the flag is off, passes untouched.
        def validate_jsonrpc_request_meta!
          return unless ::Feature.enabled?(:mcp_server_stateless_protocol, current_user)
          return if params[:method] == 'initialize' || jsonrpc_notification?

          meta = RequestMeta.from_jsonrpc_params(params[:params])

          if meta.unsupported_protocol_version?
            render_structured_api_error!({
              jsonrpc: JSONRPC_VERSION,
              error: JSONRPC_ERRORS[:unsupported_protocol_version].merge(
                data: {
                  supported: ::API::Mcp::Handlers::InitializeRequest::SUPPORTED_PROTOCOL_VERSIONS,
                  requested: meta.protocol_version
                }
              ),
              id: jsonrpc_request_id
            }, 400)
          elsif meta.modern? && meta.client_capabilities_missing?
            render_structured_api_error!({
              jsonrpc: JSONRPC_VERSION,
              error: JSONRPC_ERRORS[:invalid_params].merge(
                data: { params: "Missing required _meta key '#{RequestMeta::CLIENT_CAPABILITIES_KEY}'" }
              ),
              id: jsonrpc_request_id
            }, 400)
          end
        end

        # Renders a 400 Invalid Request. The request id is echoed only when it is one the JSON-RPC
        # spec allows, so a missing or invalid id leaves the `id` key out of the response.
        #
        # @param validations [Array<String>] the validation messages to report
        def render_invalid_jsonrpc_request!(validations)
          response = {
            jsonrpc: JSONRPC_VERSION,
            error: JSONRPC_ERRORS[:invalid_request].merge({ data: { validations: validations } })
          }
          request_id = jsonrpc_request_id
          response[:id] = request_id unless request_id.nil?

          render_structured_api_error!(response, 400)
        end

        def render_invalid_jsonrpc_params!(message)
          render_structured_api_error!({
            jsonrpc: JSONRPC_VERSION,
            error: JSONRPC_ERRORS[:invalid_params].merge({ data: { params: message } }),
            id: jsonrpc_request_id
          }, 400)
        end

        def method_not_found!(method_name)
          render_structured_api_error!({
            jsonrpc: JSONRPC_VERSION,
            error: JSONRPC_ERRORS[:method_not_found].merge({ data: { method: method_name } }),
            id: params[:id]
          }, 404)
        end

        def format_jsonrpc_response(result)
          if params[:id].nil? || result.nil?
            # MCP requires 202 Accepted with no body for a notification. `body false` would answer 204
            # and a plain '' would be JSON-dumped to `""`, so the body is an empty Precompiled.
            status :accepted
            body Gitlab::Json::Precompiled.new('')
          else
            { jsonrpc: JSONRPC_VERSION, result: result, id: params[:id] }
          end
        end
      end
    end
  end
end
