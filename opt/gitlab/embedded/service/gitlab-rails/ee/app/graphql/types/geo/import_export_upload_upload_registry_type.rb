# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class ImportExportUploadUploadRegistryType < BaseObject
      graphql_name 'ImportExportUploadUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of an import/export archive upload.'

      field :import_export_upload_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the import/export archive upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
