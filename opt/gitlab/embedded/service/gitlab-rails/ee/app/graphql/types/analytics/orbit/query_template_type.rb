# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class QueryTemplateType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitQueryTemplate'
        description 'Named query that Orbit defines, rendered for the current user.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :description, GraphQL::Types::String, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Description of the query.'
        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the query. Run it with `POST /api/v4/orbit/query/:name`.'
        field :query, GraphQL::Types::String, null: false, hash_key: :raw_query,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'GQL query text.'
      end
    end
  end
end
