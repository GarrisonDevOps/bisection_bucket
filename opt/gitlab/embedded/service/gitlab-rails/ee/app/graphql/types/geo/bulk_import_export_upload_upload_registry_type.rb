# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class BulkImportExportUploadUploadRegistryType < BaseObject
      graphql_name 'BulkImportExportUploadUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a `bulk_import_export_upload_upload`'

      field :bulk_import_export_upload_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the bulk import/export archive upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
