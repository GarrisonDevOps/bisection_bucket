# frozen_string_literal: true

module Types
  module Security
    module FindingReportsComparer
      # rubocop: disable Graphql/AuthorizeTypes -- Parent node applies authorization
      class ScannerType < BaseObject
        graphql_name 'ComparedSecurityReportScanner'
        description 'Represents a compared report vulnerability scanner'

        field :name, GraphQL::Types::String,
          null: true, description: 'Name of the vulnerability scanner.'

        field :external_id, GraphQL::Types::String,
          null: true, description: 'External ID of the vulnerability scanner.'

        field :vendor, GraphQL::Types::String,
          null: true, description: 'Vendor of the vulnerability scanner.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
