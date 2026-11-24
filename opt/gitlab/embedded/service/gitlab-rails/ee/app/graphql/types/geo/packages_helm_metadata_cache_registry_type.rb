# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included in the RegistryType
    class PackagesHelmMetadataCacheRegistryType < BaseObject
      graphql_name 'PackagesHelmMetadataCacheRegistry'
      description 'Represents the Geo replication and verification state of a packages_helm_metadata_cache.'

      include ::Types::Geo::RegistryType

      field :packages_helm_metadata_cache_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Helm Metadata Cache.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
