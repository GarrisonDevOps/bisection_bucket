# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      module StatusResolvable
        include ::Analytics::Orbit::TargetResolver

        GRPC_ERROR_MESSAGE = ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError::GENERIC_MESSAGE
        MAX_TRAVERSAL_PATHS_PER_CALL = 100

        private

        def orbit_traversal_path
          return unless ::Analytics::KnowledgeGraph.status_accessible_for_request?(current_user)

          build_graph_status_context(object)&.fetch(:traversal_path)
        end

        def batch_orbit_status(rate_limit_key)
          traversal_path = orbit_traversal_path
          return unless traversal_path

          BatchLoader::GraphQL.for(traversal_path).batch(key: rate_limit_key) do |traversal_paths, loader|
            authorization_context = ::Analytics::KnowledgeGraph::AuthorizationContext.for(current_user)
            request_context = orbit_request_context

            authorization_context.traversal_paths_in_scope(traversal_paths)
              .each_slice(MAX_TRAVERSAL_PATHS_PER_CALL) do |paths|
              check_orbit_rate_limit!(rate_limit_key)

              statuses = call_orbit { |client| yield client, paths, request_context }
              statuses&.each { |status| loader.call(status[:traversal_path], status) }
            rescue ::Gitlab::Graphql::Errors::ResourceNotAvailable => e
              paths.each { |path| loader.call(path, e.class.new(e.message)) }
            end
          end
        end

        def call_orbit
          yield ::Analytics::KnowledgeGraph::GrpcClient.new
        rescue ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError => e
          return if e.grpc_code == ::GRPC::Core::StatusCodes::UNIMPLEMENTED

          raise_resource_not_available_error! GRPC_ERROR_MESSAGE
        rescue ::Analytics::KnowledgeGraph::GrpcClient::AuthorizationError
          raise_resource_not_available_error! GRPC_ERROR_MESSAGE
        end

        def check_orbit_rate_limit!(rate_limit_key)
          return unless ::Gitlab::ApplicationRateLimiter.throttled?(
            rate_limit_key,
            scope: { user: current_user },
            users_allowlist: ::Gitlab::CurrentSettings.orbit_rate_limit_allowlist
          )

          raise_resource_not_available_error! ::Gitlab::ApplicationRateLimiter.throttled_error_message
        end

        def orbit_request_context
          request = context[:request]
          return ::Analytics::KnowledgeGraph::RequestContext.new unless request

          access_token = context[:access_token]
          oauth_access_token = access_token if access_token.is_a?(::OauthAccessToken)

          ::Analytics::KnowledgeGraph::RequestContext.from_request(
            request,
            source_type: ::Analytics::KnowledgeGraph::SourceType.for_orbit_request(
              request: request, oauth_access_token: oauth_access_token
            ),
            access_token: access_token
          )
        end
      end
    end
  end
end
