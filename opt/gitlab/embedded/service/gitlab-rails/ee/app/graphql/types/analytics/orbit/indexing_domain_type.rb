# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class IndexingDomainType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitIndexingDomain'
        description 'Indexing status of one Orbit domain.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :name, GraphQL::Types::String, null: false,
          description: 'Name of the domain.'
        field :phase, IndexingPhaseEnum, null: true,
          description: 'Indexing phase of the domain.'
      end
    end
  end
end
