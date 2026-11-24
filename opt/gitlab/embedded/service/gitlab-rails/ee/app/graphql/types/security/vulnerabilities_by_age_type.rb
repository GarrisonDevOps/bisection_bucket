# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes, GraphQL/ExtractType -- not applicable
    class VulnerabilitiesByAgeType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'VulnerabilitiesByAge'
      description 'Represents vulnerability metrics by age with filtering and grouping capabilities'

      # Only SecurityMetrics.vulnerabilitiesByAge returns it.
      authorize_granular_token skip_reason: :parent_authorizes

      field :name,
        GraphQL::Types::String,
        null: false,
        description: 'Age band name ("< 7 days", "7 - 14 days",
"15 - 30 days", "31 - 60 days", "61 - 90 days", "91 - 180 days", "> 180 days" ).'

      field :count,
        GraphQL::Types::Int,
        null: true,
        description: 'Number of vulnerabilities in the age band.'

      field :by_severity,
        [Types::Security::VulnerabilitySeverityCountType],
        null: true,
        description: 'Vulnerability counts grouped by severity level.'

      field :by_report_type,
        [Types::Security::VulnerabilityReportTypeCountType],
        null: true,
        description: 'Vulnerability counts grouped by report type.'
    end
    # rubocop: enable Graphql/AuthorizeTypes, GraphQL/ExtractType
  end
end
