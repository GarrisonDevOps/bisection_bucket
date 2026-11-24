# frozen_string_literal: true

module Mcp
  module Tools
    module Base
      class ApiTool
        extend ::Gitlab::Utils::Override

        include Mcp::Tools::Concerns::GovernanceContainerResolver
        include Mcp::Tools::Base::RateLimitedResponse

        attr_reader :name, :route, :settings, :version

        # Grape types are represented as a string by calling `.to_s` on a type
        # The values are built based on the existing routes:
        # - [String, Integer] is usually a type of an id, which can be represented as a string
        # - Grape::API::Boolean is a boolean
        # - [Integer] is an array of integers
        # - [String] represents a comma-separated string
        # - Date and DateTime are passed over the wire as an ISO 8601 string
        TYPE_CONVERSIONS = {
          '[String, Integer]' => 'string',
          'Grape::API::Boolean' => 'boolean',
          '[Integer]' => { type: 'array', items: { type: 'integer' } },
          '[String]' => 'string',
          'Date' => 'string',
          'DateTime' => 'string'
        }.freeze

        ARRAY_TYPE_PATTERN = /^Array\[(\w+)\]$/

        GENERIC_NOT_FOUND_MESSAGE = '404 Not Found'

        # Marks a route call as dispatched by the MCP server. Rack only puts headers in the
        # env under `HTTP_` keys, so an external request can't set this one.
        DISPATCH_ENV_KEY = 'gitlab.mcp.tool_dispatch'
        # Set around the in-process route call so the request logger skips it.
        SKIP_REQUEST_LOGGING_ENV_KEY = ::Gitlab::GrapeLogging::Middleware::RequestLogger::SKIP_ENV_KEY
        # Internal result metadata for the route's HTTP status.
        ROUTE_STATUS_KEY = :route_status

        def initialize(name:, route:)
          @name = name
          @route = route
          @settings = route.app.route_setting(:mcp)
          @version = @settings[:version] || "0.1.0"
        end

        override :ungovernable?
        def ungovernable?
          return true if settings[:ungovernable]

          super
        end

        override :container_arguments
        def container_arguments
          return {} if ungovernable?

          base = case route_boundary_type
                 when :project then { project: :id }
                 when :group then { group: :id }
                 else super
                 end

          base.merge(settings.fetch(:container_arguments, {}))
        end

        override :run_record_resolver
        def run_record_resolver(resolver, value)
          value = Mcp::Tools::Concerns::UrlParser.unescape_and_scrub_uri(value) if value.is_a?(String)

          super
        end

        def description
          route.description
        end

        def input_schema
          params = route.params.slice(*settings[:params].map(&:to_s))
          required_fields = params.filter_map do |param, values|
            param if values[:required]
          end

          properties = params.transform_values do |value|
            parsed_type = parse_type(value[:type])
            property =
              if parsed_type.is_a?(Hash)
                parsed_type.merge(description: value[:desc])
              else
                { type: parsed_type, description: value[:desc] }
              end

            enum = parse_enum(value[:values])
            enum ? property.merge(enum: enum) : property
          end

          Mcp::Tools::Base::SchemaDefaults.with_additional_properties(
            type: 'object',
            properties: properties,
            required: required_fields
          )
        end

        def icons
          IconConfig.gitlab_icons
        end

        def execute(request: nil, params: nil)
          args = params[:arguments]&.slice(*settings[:params]) || {}
          decode_container_arguments!(args)
          request.env[Grape::Env::GRAPE_ROUTING_ARGS].merge!(args)
          request.env[::Gitlab::Auth::ScopeValidator::MCP_TOOL_CALL_ENV_KEY] = true

          status, headers, body = execute_route(request)

          process_response(status, Array(body)[0], headers).merge(ROUTE_STATUS_KEY => status)
        end

        def tool_aliases
          Array(settings[:tool_aliases]).map(&:to_s)
        end

        def annotations
          settings[:annotations] || {}
        end

        def toolset
          settings[:toolset] || Toolsets::UNASSIGNED
        end

        def unlisted?
          settings[:unlisted].present?
        end

        def available?(_current_user)
          true
        end

        private

        def execute_route(request)
          env = request.env

          original_method = env[Rack::REQUEST_METHOD]
          original_format = env['api.format']
          original_input = env[Rack::RACK_INPUT]
          original_dispatch = env[DISPATCH_ENV_KEY]

          env[Rack::REQUEST_METHOD] = route.request_method

          begin
            # The body is the JSON-RPC envelope; without this, its keys (such as `id`) end up in the route's params.
            env[Rack::RACK_INPUT] = StringIO.new
            env[DISPATCH_ENV_KEY] = true
            env[SKIP_REQUEST_LOGGING_ENV_KEY] = true

            route.app.call(env)
          ensure
            env.delete(SKIP_REQUEST_LOGGING_ENV_KEY)
            env[Rack::REQUEST_METHOD] = original_method
            env['api.format'] = original_format
            env[Rack::RACK_INPUT] = original_input
            restore_env(env, DISPATCH_ENV_KEY, original_dispatch)
          end
        end

        def restore_env(env, key, original)
          if original.nil?
            env.delete(key)
          else
            env[key] = original
          end
        end

        # Rack percent-decodes path segments before Grape sees them; this in-process call
        # skips Rack, so the URL-encoded path the route docs advertise is decoded here.
        # A '%' is data in any other argument.
        def decode_container_arguments!(args)
          declared_argument_names.each do |name|
            key = args.key?(name) ? name : name.to_sym
            value = args[key]

            args[key] = Mcp::Tools::Concerns::UrlParser.unescape_and_scrub_uri(value) if value.is_a?(String)
          end
        end

        def route_boundary_type
          authorization = route.app.route_setting(:authorization)

          authorization[:boundary_type] if authorization.is_a?(Hash)
        end

        def parse_type(type)
          return TYPE_CONVERSIONS[type] if TYPE_CONVERSIONS.key?(type)

          # Handle Array[Type] format (e.g., 'Array[Integer]', 'Array[String]')
          if type.match?(ARRAY_TYPE_PATTERN)
            inner_type = type.match(ARRAY_TYPE_PATTERN)[1].downcase
            return { type: 'array', items: { type: inner_type } }
          end

          type.downcase
        end

        # Mirrors Grape::Validations::Validators::ValuesValidator#check_values?: only
        # zero-arity procs produce an enumerable list of allowed values. Procs that take
        # an argument are predicates (validated per-value), not something to enumerate.
        def parse_enum(values)
          zero_arity_proc = values.is_a?(Proc) && values.arity == 0
          return unless values.is_a?(Array) || zero_arity_proc

          resolved = values.is_a?(Proc) ? values.call : values
          resolved if resolved.is_a?(Array)
        rescue StandardError
          nil
        end

        def process_response(status, body, headers = nil)
          return rate_limited_response(body, headers) if status == TOO_MANY_REQUESTS

          parsed_response = Gitlab::Json.safe_parse(body)
          if status >= 400
            message =
              if status == 404 && settings[:resource_name] && generic_not_found?(parsed_response)
                resource_not_found_message
              else
                parsed_response['error'] || parsed_response['message'] || "HTTP #{status}"
              end

            ::Mcp::Tools::Base::Response.error(
              message, parsed_response, reason: ::Mcp::Tools::Base::Response.reason_for_http_status(status)
            )
          else
            formatted_content = [{ type: 'text', text: body }]
            ::Mcp::Tools::Base::Response.success(formatted_content, parsed_response)
          end
        rescue JSON::ParserError
          if status >= 400
            ::Mcp::Tools::Base::Response.error(
              "HTTP #{status}", { body: body }, reason: ::Mcp::Tools::Base::Response.reason_for_http_status(status)
            )
          else
            # Plain text response (e.g. job trace); return as-is
            formatted_content = [{ type: 'text', text: body }]
            ::Mcp::Tools::Base::Response.success(formatted_content)
          end
        end

        def resource_not_found_message
          "404 #{settings[:resource_name].capitalize} Not Found"
        end

        def generic_not_found?(parsed_response)
          parsed_response['message']&.casecmp?(GENERIC_NOT_FOUND_MESSAGE)
        end
      end
    end
  end
end
