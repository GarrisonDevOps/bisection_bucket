# frozen_string_literal: true

module Analytics
  module Orbit
    module CommandInterceptor
      CommandError = Class.new(StandardError)
      EnabledNamespacesRequiredError = Class.new(CommandError)

      OrbitQuery = Struct.new(:query_args, :response)

      def normalize_orbit_command_names(value)
        case value
        when nil
          []
        when String
          value.split(',').map(&:strip).reject(&:blank?)
        when Array
          value.map(&:to_s).map(&:strip).reject(&:blank?)
        else
          raise CommandError, "'command_names' must be an Array or comma-separated String"
        end
      end

      def orbit_command_text(result)
        result.is_a?(Hash) && result.key?(:formatted_text) ? result[:formatted_text].to_s : result.to_json
      end

      def orbit_command_format(arguments)
        raw_format = arguments['format'] || arguments[:format]
        format = raw_format&.to_sym
        %i[raw gql].include?(format) ? format : :llm
      end

      def invoke_orbit_command(command_name, parameters, user:, grpc_client:, request_context:, mcp_request_id: nil)
        if command_name == 'query_graph'
          return build_query_graph(parameters, user: user, mcp_request_id: mcp_request_id,
            request_context: request_context)
        end

        grpc_client.invoke_agent_command(
          command_name: command_name, parameters: parameters, user: user, request_context: request_context
        )
      end

      private

      def build_query_graph(parameters, user:, mcp_request_id:, request_context:)
        require_enabled_namespaces_for_command!(user)
        format = orbit_command_format(parameters)

        query = parameters['query'] || parameters[:query]
        raise CommandError, "'query' must be GQL text" unless query.nil? || query.is_a?(String)
        raise CommandError, "Missing required parameter 'query'" if query.blank?

        ::Analytics::KnowledgeGraph::GoverningNamespaceGuard.ensure_selected!(user)

        OrbitQuery.new({
          query: query,
          user: user,
          format: format,
          mcp_id: mcp_request_id,
          request_context: request_context
        })
      end

      def require_enabled_namespaces_for_command!(user)
        context = ::Analytics::KnowledgeGraph::AuthorizationContext.for(user)
        return context if context.has_enabled_namespaces?

        raise EnabledNamespacesRequiredError, 'No Knowledge Graph enabled namespaces available'
      end
    end
  end
end
