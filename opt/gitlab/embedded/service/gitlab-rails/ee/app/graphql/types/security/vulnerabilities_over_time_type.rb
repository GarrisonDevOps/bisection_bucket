# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes, GraphQL/ExtractType -- not applicable
    class VulnerabilitiesOverTimeType < BaseObject
      graphql_name 'VulnerabilitiesOverTime'
      description 'Represents vulnerability metrics over time with filtering and grouping capabilities'

      # Only SecurityMetrics.vulnerabilitiesOverTime returns it.
      authorize_granular_token skip_reason: :parent_authorizes

      field :date, GraphQL::Types::ISO8601Date, null: false, description: 'Date for the metrics.'

      field :count, GraphQL::Types::Int, null: false, description: 'Total number of vulnerabilities for the date.'

      field :by_severity, [Types::Security::VulnerabilitySeverityCountType],
        null: true,
        description: 'Vulnerability counts grouped by severity level.'

      field :by_report_type, [Types::Security::VulnerabilityReportTypeCountType],
        null: true,
        description: 'Vulnerability counts grouped by report type.'
    end
    # rubocop: enable Graphql/AuthorizeTypes, GraphQL/ExtractType
  end
end
