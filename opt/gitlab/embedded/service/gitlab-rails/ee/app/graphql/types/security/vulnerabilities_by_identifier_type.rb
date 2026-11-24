# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- not applicable
    class VulnerabilitiesByIdentifierType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'VulnerabilitiesByIdentifier'
      description 'Represents vulnerability metrics by identifier with filtering'

      # Only SecurityMetrics.vulnerabilitiesByIdentifier returns it.
      authorize_granular_token skip_reason: :parent_authorizes

      field :name,
        GraphQL::Types::String,
        null: false,
        description: 'Identifier name.'

      field :url,
        GraphQL::Types::String,
        null: true,
        description: 'URL to the identifier on the MITRE website.'

      field :count,
        GraphQL::Types::Int,
        null: true,
        description: 'Number of vulnerabilities for the identifier.'

      field :by_severity,
        [Types::Security::VulnerabilitySeverityCountType],
        null: true,
        description: 'Vulnerability counts grouped by severity level.'
    end

    # rubocop: enable Graphql/AuthorizeTypes
  end
end
