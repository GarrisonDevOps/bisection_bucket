# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class IndexingAreaType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitIndexingArea'
        description 'Indexing state of one Orbit area.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the area.'
        field :state, IndexingStateEnum, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :phase,
          description: 'Indexing state of the area.'
      end
    end
  end
end
