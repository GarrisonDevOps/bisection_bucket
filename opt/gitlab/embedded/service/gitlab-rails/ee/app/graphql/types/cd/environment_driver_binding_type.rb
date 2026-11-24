# frozen_string_literal: true

module Types
  module Cd
    class EnvironmentDriverBindingType < ::Types::BaseObject
      graphql_name 'CdEnvironmentDriverBinding'
      description 'Continuous deployment environment driver binding.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_environment
      authorize_granular_token permissions: :read_cd_environment,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::EnvironmentDriverBinding],
        null: false,
        description: 'Global ID of the environment driver binding.'

      field :version, GraphQL::Types::Int,
        null: false,
        description: 'Version of the environment driver binding.'

      field :driver_ref, GraphQL::Types::String,
        null: false,
        description: 'Reference of the driver.'

      # rubocop:disable GraphQL/ExtractType -- driver_ref and driver_config are both simple driver identifiers,
      # not a logical sub-grouping worth extracting into their own type
      # rubocop:disable Graphql/JSONType -- driver_config is genuinely unstructured: its shape is defined by
      # whichever driver produced it (see Cd::DeployDrivers::Registry and the model's schema validation)
      field :driver_config, GraphQL::Types::JSON,
        null: false,
        description: "Configuration of the environment driver binding, defined by the driver's own schema.",
        experiment: { milestone: '19.2' }
      # rubocop:enable Graphql/JSONType
      # rubocop:enable GraphQL/ExtractType

      field :environment, ::Types::Cd::EnvironmentType,
        null: true,
        description: 'Environment the driver binding belongs to.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the environment driver binding was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the environment driver binding was last updated.'

      def environment
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Environment, object.environment_id).find
      end
    end
  end
end
