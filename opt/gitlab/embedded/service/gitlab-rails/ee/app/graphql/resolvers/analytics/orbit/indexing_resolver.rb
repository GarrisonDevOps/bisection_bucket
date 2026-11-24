# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      # rubocop:disable Graphql/ResolverType -- the cop matches only multi-statement class bodies
      class IndexingResolver < IndexingStatusResolver
        type ::Types::Analytics::Orbit::IndexingType, null: true
      end
      # rubocop:enable Graphql/ResolverType
    end
  end
end
