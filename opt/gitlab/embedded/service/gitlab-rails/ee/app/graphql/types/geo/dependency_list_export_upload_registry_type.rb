# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class DependencyListExportUploadRegistryType < BaseObject
      graphql_name 'DependencyListExportUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a `dependency_list_export_upload`'

      field :dependency_list_export_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Dependency List Export Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
