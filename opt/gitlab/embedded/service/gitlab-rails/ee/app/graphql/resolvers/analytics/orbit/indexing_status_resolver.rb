# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class IndexingStatusResolver < BaseResolver
        include StatusResolvable

        type ::Types::Analytics::Orbit::IndexingStatusType, null: true

        def resolve
          batch_orbit_status(:orbit_indexing_status) do |client, paths, request_context|
            client.get_indexing_status(user: current_user, traversal_paths: paths, request_context: request_context)
              .fetch(:statuses)
          end
        end
      end
    end
  end
end
