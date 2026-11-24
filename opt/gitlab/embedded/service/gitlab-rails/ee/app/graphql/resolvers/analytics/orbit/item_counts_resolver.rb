# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class ItemCountsResolver < BaseResolver
        include StatusResolvable

        extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: MAX_TRAVERSAL_PATHS_PER_CALL

        type ::Types::Analytics::Orbit::ItemCountsType, null: true

        def resolve
          batch_orbit_status(:orbit_item_counts) do |client, paths, request_context|
            client.get_item_counts(user: current_user, traversal_paths: paths, request_context: request_context)
              .fetch(:namespaces)
          end
        end
      end
    end
  end
end
