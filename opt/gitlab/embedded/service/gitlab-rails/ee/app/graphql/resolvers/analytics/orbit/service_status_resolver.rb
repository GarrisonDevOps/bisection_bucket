# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class ServiceStatusResolver < BaseResolver
        include StatusResolvable

        extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

        type ::Types::Analytics::Orbit::ServiceStatusType, null: true

        def resolve
          return unless ::Analytics::KnowledgeGraph.status_accessible_for_request?(current_user)

          call_orbit do |client|
            client.get_cluster_health(user: current_user, request_context: orbit_request_context)
          end
        end
      end
    end
  end
end
