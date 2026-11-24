# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class SchemaResolver < BaseResolver
        include StatusResolvable

        extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

        type ::Types::Analytics::Orbit::SchemaType, null: true

        def resolve
          return unless ::Analytics::KnowledgeGraph.status_accessible_for_request?(current_user)

          call_orbit do |client|
            client.get_graph_schema(user: current_user, expand_nodes: ['*'], request_context: orbit_request_context)
              .presence
          end
        end
      end
    end
  end
end
