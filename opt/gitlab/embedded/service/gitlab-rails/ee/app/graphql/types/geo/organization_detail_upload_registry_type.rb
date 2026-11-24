# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class OrganizationDetailUploadRegistryType < BaseObject
      graphql_name 'OrganizationDetailUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of an `organization_detail_upload`'

      field :organization_detail_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Organization Detail Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
