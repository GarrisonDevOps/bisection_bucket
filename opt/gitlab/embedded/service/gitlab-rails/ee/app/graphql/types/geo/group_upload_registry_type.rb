# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class GroupUploadRegistryType < BaseObject
      graphql_name 'GroupUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a group_upload'

      field :group_upload_id, GraphQL::Types::ID, null: false, description: 'ID of the Group Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
