# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class AlertManagementMetricImageUploadRegistryType < BaseObject
      graphql_name 'AlertManagementMetricImageUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a alert_management_metric_image_upload'

      field :alert_management_metric_image_upload_id, GraphQL::Types::ID, null: false,
        description: 'ID of the Alert Management Metric Image Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
