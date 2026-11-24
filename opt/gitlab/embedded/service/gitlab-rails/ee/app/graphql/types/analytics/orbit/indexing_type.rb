# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class IndexingType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitIndexing'
        description 'Indexing state of a group or project in Orbit.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :areas, [IndexingAreaType], null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :domains,
          description: 'Indexing state of each area.'
        field :last_completed_at, ::Types::TimeType, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          experiment: { milestone: '19.4' },
          description: 'Timestamp when Orbit last completed indexing of the group or project. ' \
            'Null until the first indexing run completes, and when Orbit is not available to the current user.'
        field :projects, IndexingProjectsType, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Indexing progress of the projects in the group or project.'
        field :state, IndexingStateEnum, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :phase,
          description: 'Indexing state of the group or project.'
      end
    end
  end
end
