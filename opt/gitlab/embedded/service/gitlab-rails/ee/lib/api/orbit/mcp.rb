# frozen_string_literal: true

module API
  module Orbit
    class Mcp < ::API::Base
      include ::API::Concerns::AiWorkflowsAccess
      include ::API::Helpers::HeadersHelpers
      include APIGuard
      include ::API::Helpers::Mcp::JsonRpc::Constants

      helpers ::API::Helpers::Mcp::AuthChallenge
      helpers ::API::Helpers::Mcp::JsonRpc
      helpers ::API::Orbit::QueryResponseHelpers

      InternalError = Class.new(StandardError)

      JSONRPC_METHOD_HANDLERS = {
        'initialize' => McpHandlers::InitializeRequest,
        'notifications/initialized' => McpHandlers::InitializedNotification,
        'tools/list' => McpHandlers::ListTools,
        'tools/call' => McpHandlers::CallTool,
        'ping' => McpHandlers::Ping
      }.freeze

      feature_category :knowledge_graph
      allow_access_with_scope [:mcp_orbit, :mcp, :read_api]
      allow_ai_workflows_access
      urgency :low

      before do
        authenticate!
        unauthorized! unless access_token

        not_found! unless ::Analytics::KnowledgeGraph.enabled_for?(current_user)
        forbidden! unless ::Analytics::KnowledgeGraph::OrbitLicense.available_for?(current_user)
      end

      helpers do
        def rate_limit_mcp_command!
          return unless params[:method] == 'tools/call'

          call_params = params[:params] || {}
          return unless call_params[:name] == 'invoke_command'

          arguments = call_params[:arguments] || {}
          return unless arguments[:command_name] == 'query_graph'

          check_orbit_query_rate_limit!
        end

        def invoke_basic_handler
          method_name = params[:method]
          handler_class = JSONRPC_METHOD_HANDLERS[method_name]

          # Accept a notification (no id) that has no handler, such as notifications/cancelled.
          return if handler_class.nil? && params[:id].nil?

          method_not_found!(method_name) unless handler_class

          grpc_client = ::Analytics::KnowledgeGraph::GrpcClient.new
          handler_class.new(
            params[:params] || {}, access_token, current_user,
            grpc_client: grpc_client,
            mcp_request_id: params[:id],
            request_context: ::Analytics::KnowledgeGraph::RequestContext.for_mcp_request(
              request, access_token: access_token
            )
          ).invoke
        end
      end

      namespace 'orbit/mcp' do
        params do
          requires :jsonrpc, type: String, desc: 'JSON-RPC protocol version identifier. Must be `2.0`.',
            allow_blank: false, values: [JSONRPC_VERSION]
          requires :method, type: String, desc: 'Name of the JSON-RPC method invoked on the MCP server.',
            allow_blank: false
          # `id` must be echoed back with the same type. The identity `coerce_with` preserves it;
          # without it Grape coerces to the first matching `types` entry.
          optional :id, types: [Integer, String], coerce_with: ->(value) { value },
            desc: 'ID of the JSON-RPC request returned in the response.',
            allow_blank: false
          optional :params, desc: 'Object or array that contains parameters passed to the specified JSON-RPC method',
            types: [Hash, Array]
        end

        rescue_from Grape::Exceptions::ValidationErrors do |e|
          render_invalid_jsonrpc_request!(e.full_messages)
        end

        rescue_from ArgumentError do |e|
          render_invalid_jsonrpc_params!(e.message)
        end

        rescue_from ::Analytics::KnowledgeGraph::GoverningNamespaceGuard::RequiredError do |e|
          render_structured_api_error!({
            jsonrpc: JSONRPC_VERSION,
            error: JSONRPC_ERRORS[:invalid_request].merge({ data: e.contract.as_json }),
            id: jsonrpc_request_id
          }, 422)
        end

        rescue_from ::API::Orbit::Mcp::InternalError do |e|
          Gitlab::ErrorTracking.track_exception(e)
          render_structured_api_error!({
            jsonrpc: JSONRPC_VERSION,
            error: JSONRPC_ERRORS[:internal_error],
            id: jsonrpc_request_id
          }, 200)
        end

        desc 'MCP Orbit JSON-RPC request handler' do
          detail 'Handles JSON-RPC 2.0 requests for the Orbit Knowledge Graph MCP server'
          success code: 200
          tags %w[mcp]
          hidden true
        end
        route_setting :openapi_hidden_reason, :other_protocol
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        post do
          # Reject a missing request id before any rate limiting, gRPC client or tool is involved.
          reject_missing_jsonrpc_request_id!
          validate_jsonrpc_request_meta!

          status :ok

          rate_limit_mcp_command!

          result = invoke_basic_handler

          if result.is_a?(McpHandlers::Base::OrbitQuery)
            render_orbit_query!(**result.query_args)
          else
            format_jsonrpc_response(result)
          end
        end

        desc 'MCP Orbit SSE listener' do
          detail 'Returns 405 as the Orbit MCP server uses POST only'
          success code: 405
          tags %w[mcp]
          hidden true
        end
        route_setting :openapi_hidden_reason, :other_protocol
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        get do
          status :method_not_allowed
        end
      end
    end
  end
end

API::Orbit::Mcp.prepend_mod
