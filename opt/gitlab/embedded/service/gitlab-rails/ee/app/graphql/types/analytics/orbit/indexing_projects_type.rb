# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class IndexingProjectsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitIndexingProjects'
        description 'Indexing progress of the projects in a group or project.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :gaps, GraphQL::Types::Int, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Number of projects that are not indexed.'
        field :indexed, GraphQL::Types::Int, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Number of indexed projects.'
        field :not_indexed, GraphQL::Types::Int, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :gaps,
          experiment: { milestone: '19.4' },
          description: 'Number of projects that are not indexed.'
        field :total, GraphQL::Types::Int, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :total_known,
          experiment: { milestone: '19.4' },
          description: 'Number of projects known to Orbit.'
        field :total_known, GraphQL::Types::Int, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Number of projects known to Orbit.'
      end
    end
  end
end
