# frozen_string_literal: true

module API
  module Orbit
    module McpHandlers
      class CallTool < Base
        include ::Analytics::Orbit::CommandInterceptor

        def invoke
          tool_name = params[:name]
          arguments = params[:arguments] || {}

          raise ArgumentError, "Missing required parameter 'name'" if tool_name.blank?
          raise ArgumentError, "Arguments must be a Hash" unless arguments.is_a?(Hash)
          raise ArgumentError, "Unknown tool: #{tool_name}" unless ToolCatalog::COMMAND_TOOL_NAMES.include?(tool_name)

          result = dispatch_tool(tool_name, arguments)

          return result if result.is_a?(OrbitQuery)
          return result if result.is_a?(Hash) && result[:isError]

          format_success(result)
        rescue ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError => e
          log_error('connection_error', e)
          raise ::API::Orbit::Mcp::InternalError, e.message unless e.client_error? && e.grpc_details.present?

          format_error(e.grpc_details)
        end

        private

        def dispatch_tool(tool_name, arguments)
          case tool_name
          when 'list_commands'
            dispatch_list_commands(arguments)
          when 'invoke_command'
            dispatch_invoke_command(arguments)
          end
        end

        def dispatch_list_commands(arguments)
          format = orbit_command_format(arguments)
          grpc_client.list_agent_commands(
            user: current_user,
            command_names: normalize_orbit_command_names(arguments['command_names'] || arguments[:command_names]),
            format: format,
            request_context: request_context
          )
        rescue ::Analytics::Orbit::CommandInterceptor::CommandError => e
          format_error(e.message)
        end

        def dispatch_invoke_command(arguments)
          command_name, parameters = parse_invoke_command_arguments(arguments)

          invoke_orbit_command(
            command_name, parameters,
            user: current_user, grpc_client: grpc_client, request_context: request_context,
            mcp_request_id: mcp_request_id
          )
        rescue ::Analytics::Orbit::CommandInterceptor::CommandError => e
          format_error(e.message)
        end

        def parse_invoke_command_arguments(arguments)
          args = arguments.stringify_keys
          unknown_keys = args.keys - %w[command_name parameters]
          unless unknown_keys.empty?
            raise ArgumentError,
              "Unknown top-level parameter(s) for invoke_command: #{unknown_keys.join(', ')}. " \
                "Put downstream command inputs inside 'parameters'."
          end

          command_name = args['command_name']
          raise ArgumentError, "Missing required parameter 'command_name'" if command_name.blank?

          parameters = args['parameters'] || {}
          raise ArgumentError, "'parameters' must be a Hash" unless parameters.is_a?(Hash)

          [command_name, parameters]
        end

        def format_success(result)
          ::Analytics::KnowledgeGraph::QueryRunner::McpRenderer.tool_result(orbit_command_text(result), is_error: false)
        end

        def format_error(message)
          ::Analytics::KnowledgeGraph::QueryRunner::McpRenderer.tool_result(message, is_error: true)
        end

        def log_error(type, error)
          ::Gitlab::KnowledgeGraph::Logger.build.error(
            message: "MCP Orbit call_tool #{type}",
            error: error.message,
            tool_name: params[:name]
          )
        end
      end
    end
  end
end
