# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class ServiceStatusType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitServiceStatus'
        description 'Health of the Orbit service.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :components, [ServiceComponentType], null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Health of each component of the Orbit service.'
        field :state, ServiceStateEnum, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Overall health state of the Orbit service.',
          hash_key: :status
        field :version, GraphQL::Types::String, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Version of the Orbit service.'

        def components
          object[:components] || []
        end
      end
    end
  end
end
