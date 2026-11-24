# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class PackagesDebianProjectComponentFileRegistryType < BaseObject
      graphql_name 'PackagesDebianProjectComponentFileRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a packages_debian_project_component_file'

      field :packages_debian_project_component_file_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Packages::Debian::ProjectComponentFile.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
