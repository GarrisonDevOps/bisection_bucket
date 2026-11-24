# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class ServiceComponentType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitServiceComponent'
        description 'Health of one component of the Orbit service.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the component, for example `clickhouse`.'
        field :state, ServiceStateEnum, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Health state of the component.',
          hash_key: :status
      end
    end
  end
end
