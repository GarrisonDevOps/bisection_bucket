# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class AchievementUploadRegistryType < BaseObject
      graphql_name 'AchievementUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of an `achievement_upload`'

      field :achievement_upload_id, GraphQL::Types::ID, null: false, description: 'ID of the Achievement Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
