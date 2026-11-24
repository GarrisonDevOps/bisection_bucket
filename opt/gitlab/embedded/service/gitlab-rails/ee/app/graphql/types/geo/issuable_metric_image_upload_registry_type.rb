# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class IssuableMetricImageUploadRegistryType < BaseObject
      graphql_name 'IssuableMetricImageUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a `issuable_metric_image_upload`'

      field :issuable_metric_image_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Issuable Metric Image Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
