# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class QueryTemplatesResolver < BaseResolver
        include StatusResolvable

        extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

        type [::Types::Analytics::Orbit::QueryTemplateType], null: true

        def resolve
          return unless ::Analytics::KnowledgeGraph.accessible_for?(current_user)

          templates = call_orbit do |client|
            client.list_named_queries(user: current_user, request_context: orbit_request_context)
          end

          templates || []
        end
      end
    end
  end
end
