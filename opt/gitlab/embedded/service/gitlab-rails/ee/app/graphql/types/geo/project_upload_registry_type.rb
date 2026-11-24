# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class ProjectUploadRegistryType < BaseObject
      graphql_name 'ProjectUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a project_upload'

      field :project_upload_id, GraphQL::Types::ID, null: false, description: 'ID of the Project Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
