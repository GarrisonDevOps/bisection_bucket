# frozen_string_literal: true

module Mcp
  module Tools
    module Orbit
      class CommandTool < ::Mcp::Tools::Base::BaseService
        include ::Analytics::Orbit::CommandInterceptor

        Response = ::Mcp::Tools::Base::Response

        attr_reader :description, :input_schema

        def initialize(command:, context:)
          super(name: command[:name])
          @description = command[:description]
          @input_schema = command[:parameters]
          @context = context
        end

        def version
          '0.1.0'
        end

        def toolset
          :orbit
        end

        def annotations
          { title: name.humanize(keep_id_suffix: true), readOnlyHint: true, idempotentHint: true, openWorldHint: false }
        end

        protected

        def perform(arguments = {})
          return rate_limited_error if name == 'query_graph' && query_throttled?

          result = invoke_orbit_command(
            name, arguments || {},
            user: current_user, grpc_client: ::Analytics::KnowledgeGraph::GrpcClient.new,
            request_context: ::Analytics::KnowledgeGraph::RequestContext.for_mcp_request(
              request, access_token: access_token
            ),
            mcp_request_id: request[:id]
          )
          return run_orbit_query(result) if result.is_a?(OrbitQuery)

          Response.success([{ type: Response::TEXT_CONTENT, text: orbit_command_text(result) }])
        rescue EnabledNamespacesRequiredError => e
          Response.error(e.message, reason: Response::Reason::UNAUTHORIZED)
        rescue CommandError => e
          Response.error(e.message, reason: Response::Reason::BAD_REQUEST)
        rescue ::Analytics::KnowledgeGraph::GoverningNamespaceGuard::RequiredError => e
          Response.error(e.message, e.contract.as_json, reason: Response::Reason::BAD_REQUEST)
        rescue ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError => e
          grpc_error(e)
        end

        private

        attr_reader :context

        delegate :current_user, :access_token, :request, to: :context, private: true

        def query_throttled?
          ::Gitlab::ApplicationRateLimiter.throttled_request?(
            request, current_user, :orbit_query,
            scope: { user: current_user },
            users_allowlist: ::Gitlab::CurrentSettings.orbit_rate_limit_allowlist
          )
        end

        def rate_limited_error
          Response.rate_limited_error(
            ::Gitlab::ApplicationRateLimiter.throttled_error_message,
            retry_after: ::Gitlab::ApplicationRateLimiter.period_for(:orbit_query),
            limit: :orbit_query
          )
        end

        # Runs here, not in render_mcp_result, so the outcome reaches the tool_status log.
        def run_orbit_query(orbit_query)
          query_args = orbit_query.query_args
          response = ::Analytics::KnowledgeGraph::QueryRunner.new(
            ::Analytics::KnowledgeGraph::QueryRunner.params_for(**query_args), user: current_user, env: request.env
          ).execute

          OrbitQuery.new(query_args, response)
        end

        def grpc_error(error)
          message = ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError::GENERIC_MESSAGE
          message = error.grpc_details if error.client_error? && error.grpc_details.present?

          Response.error(message, reason: grpc_reason(error.grpc_code))
        end

        def grpc_reason(code)
          codes = ::GRPC::Core::StatusCodes

          # UNAUTHENTICATED stays `error`: Orbit only returns it when it rejects Rails' own JWT.
          case code
          when codes::NOT_FOUND then Response::Reason::NOT_FOUND
          when codes::INVALID_ARGUMENT, codes::FAILED_PRECONDITION then Response::Reason::BAD_REQUEST
          else Response::Reason::ERROR
          end
        end
      end
    end
  end
end
