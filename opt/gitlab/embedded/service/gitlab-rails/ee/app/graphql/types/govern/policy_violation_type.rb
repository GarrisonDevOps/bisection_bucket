# frozen_string_literal: true

module Types
  module Govern
    # rubocop:disable Graphql/AuthorizeTypes -- Violations are only reachable through the
    # policyEvaluations field, which authorizes against the parent container (group or organization).
    class PolicyViolationType < BaseObject
      graphql_name 'GovernPolicyViolation'
      description 'Violation a policy evaluation produced.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :id, ::Types::GlobalIDType[::Govern::PolicyViolation],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Global ID of the violation.'

      # The violation details are free-form engine output with no fixed shape
      # to type yet, mirroring the permissive JSON schema on the column.
      field :details, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- free-form experiment content (see comment)
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Details of the violation.'

      field :created_at, Types::TimeType,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Timestamp of when the violation was recorded.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
