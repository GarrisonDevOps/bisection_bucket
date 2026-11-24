# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class PackagesNugetSymbolRegistryType < BaseObject
      graphql_name 'PackagesNugetSymbolRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a packages_nuget_symbol'

      field :packages_nuget_symbol_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Packages::Nuget::Symbol.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
