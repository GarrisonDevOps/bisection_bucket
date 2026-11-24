# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class IndexingStatusType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitIndexingStatus'
        description 'Indexing status of a group or project in Orbit.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :domains, [IndexingDomainType], null: true,
          description: 'Indexing status of each domain.'
        field :phase, IndexingPhaseEnum, null: true,
          description: 'Indexing phase of the group or project.'
        field :projects, IndexingProjectsType, null: true,
          description: 'Indexing progress of the projects in the group or project.'
      end
    end
  end
end
