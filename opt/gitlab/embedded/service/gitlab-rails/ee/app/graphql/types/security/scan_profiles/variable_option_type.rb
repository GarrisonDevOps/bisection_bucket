# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Static data, the same for every user
      class VariableOptionType < BaseObject
        graphql_name 'SecurityScanProfileVariableOption'
        description 'Value a scan profile configuration variable of the enum or multi-select value type can take.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :value, GraphQL::Types::String,
          null: false,
          experiment: { milestone: '19.6' },
          description: 'Value passed to the CI/CD variable.'

        field :text, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Translated display text of the option.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
