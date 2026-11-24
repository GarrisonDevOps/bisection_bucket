# frozen_string_literal: true

module Types
  module Cd
    class EnvironmentApplicationType < ::Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- composite type; authorization is enforced by the parent environment and the nested application field
      graphql_name 'CdEnvironmentApplication'
      description 'An application with services in a continuous deployment environment.'

      connection_type_class Types::CountableConnectionType

      authorize_granular_token permissions: :read_cd_environment,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :services_count, GraphQL::Types::Int,
        null: false,
        description: "Number of the application's services in the environment.",
        experiment: { milestone: '19.3' }

      field :service_environment_healths, ::Types::Cd::ServiceEnvironmentHealthType.connection_type,
        null: true,
        description: "Observed health of the application's services in the environment, " \
          'each with the versions currently deployed there.',
        experiment: { milestone: '19.3' }

      field :application, ::Types::Cd::ApplicationType,
        null: true,
        description: 'Application with services in the environment.',
        experiment: { milestone: '19.3' }

      def services_count
        object.service_environment_healths.size
      end
    end
  end
end
