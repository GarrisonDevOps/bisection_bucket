# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class DesignManagementActionUploadRegistryType < BaseObject
      graphql_name 'DesignManagementActionUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a `design_management_action_upload`'

      field :design_management_action_upload_id, GraphQL::Types::ID,
        null: false, description: 'ID of the Design Management Action Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
