# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class SchemaDomainType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitSchemaDomain'
        description 'Domain that groups related node kinds in the Orbit schema.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the domain.'
      end
    end
  end
end
