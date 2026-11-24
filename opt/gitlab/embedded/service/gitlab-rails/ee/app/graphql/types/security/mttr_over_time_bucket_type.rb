# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes, GraphQL/ExtractType -- Authorization is done in the resolver layer
    class MttrOverTimeBucketType < BaseObject
      graphql_name 'MttrOverTimeBucket'
      description 'Mean time to remediation for a single weekly (Monday to Sunday) bucket, ' \
        'with optional breakdowns by severity and report type'
      authorize_granular_token skip_reason: :parent_authorizes

      field :start_date, GraphQL::Types::ISO8601Date, null: false,
        description: 'Start of the weekly bucket (Monday).'

      field :end_date, GraphQL::Types::ISO8601Date, null: false,
        description: 'End of the weekly bucket (Sunday). Capped at the current date, ' \
          'so the most recent bucket may be partial.'

      field :sum_days, GraphQL::Types::Float, null: false,
        description: 'Sum of remediation time, in days, across vulnerabilities remediated in the bucket. ' \
          'Numerator of the MTTR average.'

      field :count, GraphQL::Types::Int, null: false,
        description: 'Number of vulnerabilities remediated in the bucket. Denominator of the MTTR average.'

      field :mttr, GraphQL::Types::Float, null: true,
        description: 'Mean time to remediation, in days (sumDays / count). ' \
          'Null when no vulnerabilities were remediated in the bucket.'

      field :by_severity, [::Types::Security::MttrOverTimeBySeverityType], null: false,
        description: 'Remediation metrics for the bucket broken down by severity.'

      field :by_report_type, [::Types::Security::MttrOverTimeByReportTypeType], null: false,
        description: 'Remediation metrics for the bucket broken down by report type.'
    end
    # rubocop: enable Graphql/AuthorizeTypes, GraphQL/ExtractType
  end
end
