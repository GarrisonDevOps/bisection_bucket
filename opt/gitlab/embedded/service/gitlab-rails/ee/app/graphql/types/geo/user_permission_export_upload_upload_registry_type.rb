# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class UserPermissionExportUploadUploadRegistryType < BaseObject
      graphql_name 'UserPermissionExportUploadUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a `user_permission_export_upload_upload`.'

      field :user_permission_export_upload_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the User Permission Export File Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
