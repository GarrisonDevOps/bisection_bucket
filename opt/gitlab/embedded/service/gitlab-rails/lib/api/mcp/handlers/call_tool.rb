# frozen_string_literal: true

module API
  module Mcp
    module Handlers
      class CallTool
        class ToolResponseError < StandardError
          attr_reader :result

          def initialize(result)
            @result = result
            super(::Mcp::Tools::Base::Response.error_message(result) || 'Tool returned an error response')
          end
        end

        TOOL_REQUIREMENTS_META_KEY = 'com.gitlab/tool_requirements'

        InvalidToolRequirementsError = Class.new(ArgumentError)

        DISPATCH_KEY = ::Mcp::Tools::Base::AggregatedService::DISPATCH_KEY
        ARGUMENT_REWRITERS = [::Gitlab::Mcp::WorkItemIdArgument, ::Gitlab::Mcp::LegacyProjectArgument].freeze
        ROUTE_STATUS_KEY = ::Mcp::Tools::Base::ApiTool::ROUTE_STATUS_KEY

        class ToolDeniedError < StandardError
          attr_reader :tool_name, :denied_by

          def initialize(tool_name, denied_by = nil)
            @tool_name = tool_name
            @denied_by = denied_by

            super(format("Tool '%{tool_name}' is denied by tool rules", tool_name: tool_name))
          end

          def result_text
            location = " in #{denied_by}" if denied_by
            "#{tool_name} is denied by an Always Deny rule#{location}."
          end
        end

        def initialize(manager)
          @manager = manager
        end

        # @param client_info [Gitlab::Mcp::ClientInfo, nil] the identity the client reports, if any
        def invoke(request, params, current_user = nil, context: nil, tool_name_prefix: nil, client_info: nil)
          @client_info = client_info
          @context = context
          @db_fields = {}
          @requested_version = nil
          tool_name = params[:name]
          listed_tool_name = tool_name.dup
          tool_name.delete_prefix!(tool_name_prefix) if tool_name_prefix.present?
          request_id = request[:id] || SecureRandom.uuid

          tool = fetch_tool(tool_name, request_id, current_user, params, listed_tool_name)
          @caller_argument_keys = tool_arguments(params)&.keys
          @normalized_arguments = normalize_arguments(tool, params, current_user)
          track_start_event(tool_name, request_id, current_user, tool: tool, params: params)
          configure_tool_credentials(tool, current_user)
          denial = enforce_tool_governance!(tool, tool_name, request_id, current_user, params)
          return denial if denial

          execute_tool_with_tracking(tool, request, params, tool_name, request_id, current_user)
        end

        private

        attr_reader :manager, :client_info, :context, :caller_argument_keys, :normalized_arguments

        def tool_arguments(params)
          params.to_h.with_indifferent_access[:arguments]
        end

        def normalize_arguments(tool, params, current_user)
          arguments = params[:arguments]
          return unless arguments.respond_to?(:key?)

          ARGUMENT_REWRITERS.flat_map { |rewriter| rewriter.normalize!(tool, arguments, current_user) }.presence
        end

        def fetch_tool(tool_name, request_id, current_user, params, listed_tool_name)
          start = current_monotonic_time
          version = requested_version(params, tool_name, listed_tool_name)
          manager.get_tool(name: tool_name, version: version, context: context)
        rescue ::Mcp::Tools::Manager::ToolNotFoundError,
          ::Mcp::Tools::Manager::VersionNotFoundError,
          ::Mcp::Tools::Manager::InvalidVersionFormatError,
          ArgumentError => e
          # Measured once so the audit event and the log line cannot report different durations.
          duration = duration_since(start)
          track_start_event(tool_name, request_id, current_user, params: params)
          track_finish_event(tool_name, request_id, current_user,
            success: false, error: e, params: params, duration_s: duration)
          log_tool_call(tool_name, request_id, current_user, params, error: e, duration_s: duration)
          raise ArgumentError, e.message
        end

        def requested_version(params, tool_name, listed_tool_name)
          meta = params[:_meta]
          return unless meta.is_a?(Hash)

          requirements = meta.to_h.with_indifferent_access[TOOL_REQUIREMENTS_META_KEY]
          return if requirements.nil?

          unless requirements.is_a?(Hash)
            raise InvalidToolRequirementsError,
              "#{TOOL_REQUIREMENTS_META_KEY} must be an object mapping tool names to exact versions"
          end

          requirements = requirements.to_h.with_indifferent_access
          key = [listed_tool_name, tool_name, manager.resolve_alias(tool_name)].find { |name| requirements.key?(name) }
          return unless key

          version = requirements[key]
          @requested_version = (version.is_a?(String) ? version : version.to_json).truncate(255)
          unless version.is_a?(String)
            raise InvalidToolRequirementsError, "#{TOOL_REQUIREMENTS_META_KEY} versions must be strings"
          end

          version
        end

        def enforce_tool_governance!(tool, tool_name, request_id, current_user, params)
          start = current_monotonic_time
          check_tool_governance!(tool, tool_name, current_user, params)
          nil
        rescue ToolDeniedError => error
          record_governance_failure(error, start, tool, tool_name, request_id, current_user, params)
          ::Mcp::Tools::Base::Response.error(error.result_text)
        rescue ArgumentError => error
          record_governance_failure(error, start, tool, tool_name, request_id, current_user, params)
          raise
        end

        def record_governance_failure(error, start, tool, tool_name, request_id, current_user, params)
          duration = duration_since(start)
          track_finish_event(tool_name, request_id, current_user,
            success: false, error: error, tool: tool, params: params, duration_s: duration)
          log_tool_call(tool_name, request_id, current_user, params,
            tool: tool, error: error, duration_s: duration)
        end

        def configure_tool_credentials(tool, current_user)
          tool.set_cred(current_user: current_user) if tool.is_a?(::Mcp::Tools::Base::AggregatedService)

          return unless tool.is_a?(::Mcp::Tools::Base::CustomService) || tool.is_a?(::Mcp::Tools::Base::GraphqlService)

          tool.set_cred(current_user: current_user, access_token: context&.access_token)
        end

        def execute_tool_with_tracking(tool, request, params, tool_name, request_id, current_user)
          start_db_counters = current_db_counters
          start = current_monotonic_time
          result = tool.execute(request: request, params: params)
          route_status = result[ROUTE_STATUS_KEY] if result.is_a?(Hash)
          failure = failed_result(result)
          raise ToolResponseError, failure if failure

          @db_fields = db_counter_fields(start_db_counters)
          duration = duration_since(start)
          dispatch = dispatch_info(result)
          track_finish_event(tool_name, request_id, current_user,
            success: true, tool: tool, params: params, duration_s: duration, dispatch: dispatch)
          log_tool_call(tool_name, request_id, current_user, params,
            tool: tool, duration_s: duration, dispatch: dispatch, route_status: route_status)
          result = result.except(DISPATCH_KEY, ROUTE_STATUS_KEY) if result.is_a?(Hash)
          result
        rescue ToolResponseError => e
          @db_fields = db_counter_fields(start_db_counters)
          duration = duration_since(start)
          dispatch = dispatch_info(e.result)
          track_finish_event(tool_name, request_id, current_user,
            success: false, error: e, tool: tool, params: params, duration_s: duration, dispatch: dispatch)
          log_tool_call(tool_name, request_id, current_user, params,
            tool: tool, error: e, duration_s: duration, dispatch: dispatch, route_status: route_status)
          result = result.except(DISPATCH_KEY, ROUTE_STATUS_KEY, :reason) if result.is_a?(Hash)
          result
        rescue StandardError => error
          @db_fields = db_counter_fields(start_db_counters)
          duration = duration_since(start)
          discard_result(result)
          track_finish_event(tool_name, request_id, current_user,
            success: false, error: error, tool: tool, params: params, duration_s: duration)
          log_tool_call(tool_name, request_id, current_user, params,
            tool: tool, error: error, duration_s: duration)
          raise error
        end

        def log_tool_call(
          tool_name, request_id, current_user, params,
          duration_s:, tool: nil, error: nil, **metadata
        )
          metadata.assert_valid_keys(:dispatch, :route_status)

          arguments = tool_arguments(params) || {}
          namespace = tool_call_namespace(tool, params)

          expanded = { arguments: filter_parameters(arguments) }
          error_fields = {}

          if error && !error.is_a?(ToolResponseError)
            error_fields[::Labkit::Fields::ERROR_TYPE] = error.class.name
            expanded[::Labkit::Fields::ERROR_MESSAGE] = error.message
          end

          logger.conditional_info(
            current_user,
            message: 'MCP tool call',
            event_name: 'tools_call',
            ai_component: 'mcp_server',
            tool_name: tool_name,
            **alias_fields(tool_name),
            tool_version: tool.try(:version),
            requested_tool_version: @requested_version,
            request_id: request_id,
            tool_status: tool_status(error),
            **route_status_fields(metadata[:route_status]),
            ::Labkit::Fields::DURATION_S => duration_s,
            **@db_fields,
            argument_keys: caller_argument_keys || arguments.keys,
            ::Labkit::Fields::GL_ROOT_NAMESPACE_ID => namespace&.id,
            namespace: namespace,
            expanded: expanded,
            **client_fields,
            **dispatch_fields(metadata[:dispatch]),
            **normalized_argument_fields,
            **error_fields
          )
        end

        def discard_result(_result); end

        def failed_result(result)
          result if ::Mcp::Tools::Base::Response.error?(result)
        end

        def dispatch_info(result)
          result[DISPATCH_KEY] if result.is_a?(Hash)
        end

        def dispatch_fields(dispatch)
          return {} unless dispatch

          { dispatched_tool_name: dispatch[:tool_name] }
        end

        def normalized_argument_fields
          return {} unless normalized_arguments

          { normalized_arguments: normalized_arguments }
        end

        def route_status_fields(route_status)
          return {} unless route_status

          { ::Labkit::Fields::HTTP_STATUS_CODE => route_status }
        end

        def client_fields
          client_info.to_h
        end

        def alias_fields(tool_name)
          canonical_name = manager.resolve_alias(tool_name)
          return {} if canonical_name == tool_name

          { canonical_tool_name: canonical_name }
        end

        def tool_status(error)
          case error
          when nil then 'ok'
          when ToolResponseError then ::Mcp::Tools::Base::Response.error_reason(error.result).to_s
          when ::Mcp::Tools::Manager::ToolNotFoundError then 'not_found'
          when ToolDeniedError then 'unauthorized'
          when ::Mcp::Tools::Concerns::GovernanceContainerResolver::TooManyContainersError,
            ::Mcp::Tools::Manager::VersionNotFoundError,
            ::Mcp::Tools::Manager::InvalidVersionFormatError,
            InvalidToolRequirementsError then 'bad_request'
          else 'error'
          end
        end

        def filter_parameters(arguments)
          ::ActiveSupport::ParameterFilter.new(::API::API::LOG_FILTERS).filter(arguments)
        end

        def logger
          ::Gitlab::Mcp::Logger.build
        end

        def current_monotonic_time
          ::Gitlab::Metrics::System.monotonic_time
        end

        def duration_since(start)
          (current_monotonic_time - start).round(6)
        end

        def current_db_counters
          ::Gitlab::Metrics::Subscribers::ActiveRecord.db_counter_payload
        end

        def db_counter_fields(start_counters)
          end_counters = current_db_counters
          fields = end_counters.each_with_object({}) do |(key, value), diff|
            delta = value - start_counters.fetch(key, 0)
            next unless log_db_counter?(key, delta, start_counters, end_counters)

            diff[key] = delta.is_a?(Float) ? delta.round(3) : delta
          end
          return fields if fields.empty?

          duration_keys = ::Gitlab::Metrics::Subscribers::ActiveRecord.load_balancing_metric_query_duration_keys
          fields.merge(db_duration_s: fields.values_at(*duration_keys).compact.sum.round(3))
        end

        def log_db_counter?(key, delta, start_counters, end_counters)
          return false if key.end_with?('_txn_max_duration_s')
          return true unless delta == 0

          string_key = key.to_s
          return false unless string_key.end_with?('_duration_s')

          count_key = :"#{string_key.delete_suffix('_duration_s')}_count"
          end_counters.fetch(count_key, 0) > start_counters.fetch(count_key, 0)
        end

        # Stub methods for CE - will be overridden in EE
        def track_start_event(tool_name, request_id, current_user, tool: nil, params: nil)
          # No-op in CE
        end

        # rubocop:disable Metrics/ParameterLists -- every field is forwarded to the EE override
        def track_finish_event(
          tool_name, request_id, current_user, success:, tool: nil, error: nil, params: nil,
          duration_s: nil, dispatch: nil
        )
          # rubocop:enable Metrics/ParameterLists
          # No-op in CE
        end

        def tool_call_namespace(_tool, _params)
          # Tool-call telemetry and expanded logging are EE-only, so CE never resolves a namespace.
        end

        def check_tool_governance!(_tool, _tool_name, _current_user, _params); end
      end
    end
  end
end

API::Mcp::Handlers::CallTool.prepend_mod
