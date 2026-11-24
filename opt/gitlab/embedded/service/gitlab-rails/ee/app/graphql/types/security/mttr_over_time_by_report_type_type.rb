# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization is done in the resolver layer
    class MttrOverTimeByReportTypeType < BaseObject
      graphql_name 'MttrOverTimeByReportType'
      description 'Mean time to remediation for a single report type within a weekly bucket'
      authorize_granular_token skip_reason: :parent_authorizes

      field :report_type, ::Types::VulnerabilityReportTypeEnum, null: false,
        description: 'Report type the breakdown applies to.'

      field :sum_days, GraphQL::Types::Float, null: false,
        description: 'Sum of remediation time, in days, across vulnerabilities of the report type remediated in ' \
          'the bucket.'

      field :count, GraphQL::Types::Int, null: false,
        description: 'Number of vulnerabilities of the report type remediated in the bucket.'

      field :mttr, GraphQL::Types::Float, null: true,
        description: 'Mean time to remediation for the report type, in days (sumDays / count). ' \
          'Null when the count is 0.'

      # The finder returns upper-case names, the enum values are lower-case.
      def report_type
        object['report_type'].downcase
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
