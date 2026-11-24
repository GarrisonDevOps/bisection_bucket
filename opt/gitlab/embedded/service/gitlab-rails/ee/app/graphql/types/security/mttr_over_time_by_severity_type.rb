# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization is done in the resolver layer
    class MttrOverTimeBySeverityType < BaseObject
      graphql_name 'MttrOverTimeBySeverity'
      description 'Mean time to remediation for a single severity within a weekly bucket'
      authorize_granular_token skip_reason: :parent_authorizes

      field :severity, ::Types::VulnerabilitySeverityEnum, null: false,
        description: 'Severity the breakdown applies to.'

      field :sum_days, GraphQL::Types::Float, null: false,
        description: 'Sum of remediation time, in days, across vulnerabilities of the severity remediated in ' \
          'the bucket.'

      field :count, GraphQL::Types::Int, null: false,
        description: 'Number of vulnerabilities of the severity remediated in the bucket.'

      field :mttr, GraphQL::Types::Float, null: true,
        description: 'Mean time to remediation for the severity, in days (sumDays / count). ' \
          'Null when the count is 0.'

      # The finder returns upper-case names, the enum values are lower-case.
      def severity
        object['severity'].downcase
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
