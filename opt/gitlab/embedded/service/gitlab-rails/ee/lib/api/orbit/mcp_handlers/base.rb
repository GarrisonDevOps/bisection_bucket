# frozen_string_literal: true

module API
  module Orbit
    module McpHandlers
      class Base
        OrbitQuery = ::Analytics::Orbit::CommandInterceptor::OrbitQuery

        attr_reader :access_token, :current_user, :params, :grpc_client, :mcp_request_id, :request_context

        def initialize(
          params, access_token, current_user,
          grpc_client: nil, mcp_request_id: nil,
          request_context: ::Analytics::KnowledgeGraph::RequestContext.new
        )
          @params = params
          @access_token = access_token
          @current_user = current_user
          @grpc_client = grpc_client || ::Analytics::KnowledgeGraph::GrpcClient.new
          @mcp_request_id = mcp_request_id
          @request_context = request_context
        end

        def invoke
          raise NoMethodError
        end
      end
    end
  end
end
