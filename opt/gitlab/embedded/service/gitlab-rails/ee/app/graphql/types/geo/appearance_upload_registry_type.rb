# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class AppearanceUploadRegistryType < BaseObject
      graphql_name 'AppearanceUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of an `appearance_upload`'

      field :appearance_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Appearance Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
