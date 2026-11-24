# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyLicenseScanningViolationType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyLicenseScanningViolation'
      description 'Represents policy violation for `license_scanning` report_type'

      field :license,
        type: GraphQL::Types::String,
        null: false,
        description: 'License name.'

      field :dependencies,
        type: [GraphQL::Types::String],
        null: false,
        description: 'List of dependencies using the violated license.'

      field :url,
        type: GraphQL::Types::String,
        null: true,
        description: 'URL of the license.'
    end
  end
end
