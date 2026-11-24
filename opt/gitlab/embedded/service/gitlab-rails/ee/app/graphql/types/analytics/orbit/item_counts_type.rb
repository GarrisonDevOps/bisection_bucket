# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class ItemCountsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitItemCounts'
        description 'Number of indexed items of a group or project in Orbit.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :areas, [ItemCountAreaType], null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :domains,
          experiment: { milestone: '19.4' },
          description: 'Number of indexed items in each area.'
        field :domains, [ItemCountDomainType], null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Number of indexed items in each domain.'
      end
    end
  end
end
