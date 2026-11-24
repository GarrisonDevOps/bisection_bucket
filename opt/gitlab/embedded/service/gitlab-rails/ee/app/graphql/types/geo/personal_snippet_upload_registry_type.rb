# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class PersonalSnippetUploadRegistryType < BaseObject
      graphql_name 'PersonalSnippetUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a personal_snippet_upload'

      field :personal_snippet_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Personal Snippet Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
