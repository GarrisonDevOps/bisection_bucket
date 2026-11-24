# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Static data, the same for every user
      class VariableType < BaseObject
        graphql_name 'SecurityScanProfileVariable'
        description 'A configuration variable that a scan profile of a given type can set.'

        authorize_granular_token permissions: :read_metadata, boundary: :instance, boundary_type: :instance

        field :key, GraphQL::Types::String,
          null: false,
          description: 'Name of the configuration field, as used in the scan profile configuration input.'

        field :env_var, GraphQL::Types::String,
          null: true,
          description: 'CI/CD variable the configuration field is passed to the scan as.'

        field :label, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Translated display name of the configuration field.'

        field :description, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Translated description of the configuration field.'

        field :value_type, ::Types::Security::ScanProfiles::VariableValueTypeEnum,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Kind of value the configuration field takes.'

        field :options, [::Types::Security::ScanProfiles::VariableOptionType],
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Values the configuration field can take, when its value type is `ENUM` or `MULTI_SELECT`.'

        field :placeholder, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Example value of the configuration field.'

        field :min, GraphQL::Types::Int,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Smallest value the configuration field accepts, when its value type is `INTEGER`.'

        field :max, GraphQL::Types::Int,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Largest value the configuration field accepts, when its value type is `INTEGER`.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
