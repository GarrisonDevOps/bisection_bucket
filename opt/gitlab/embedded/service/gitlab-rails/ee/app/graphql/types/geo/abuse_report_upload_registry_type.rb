# frozen_string_literal: true

module Types
  module Geo
    # rubocop:disable Graphql/AuthorizeTypes -- because it is included
    class AbuseReportUploadRegistryType < BaseObject
      graphql_name 'AbuseReportUploadRegistry'

      include ::Types::Geo::RegistryType

      description 'Represents the Geo replication and verification state of a abuse_report_upload'

      field :abuse_report_upload_id, GraphQL::Types::ID, null: false, description: 'ID of the Abuse Report Upload.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
