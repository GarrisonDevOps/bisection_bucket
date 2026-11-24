# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class UserUploadRegistryType < BaseObject
      graphql_name 'UserUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a `user_upload`'

      field :user_upload_id, GraphQL::Types::ID, null: false, description: 'ID of the User Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
