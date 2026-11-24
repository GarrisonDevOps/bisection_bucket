# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class ProjectImportExportRelationExportUploadUploadRegistryType < BaseObject
      graphql_name 'ProjectImportExportRelationExportUploadUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a relation export file upload ' \
        'project_import_export_relation_export_upload_upload'

      field :project_import_export_relation_export_upload_upload_id, GraphQL::Types::ID,
        null: false, description: 'ID of the Relation Export File Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
