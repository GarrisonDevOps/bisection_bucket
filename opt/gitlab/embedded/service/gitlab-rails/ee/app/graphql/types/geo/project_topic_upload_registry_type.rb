# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class ProjectTopicUploadRegistryType < BaseObject
      graphql_name 'ProjectTopicUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a `project_topic_upload`'

      field :project_topic_upload_id, GraphQL::Types::ID, null: false, description: 'ID of the Project Topic Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
