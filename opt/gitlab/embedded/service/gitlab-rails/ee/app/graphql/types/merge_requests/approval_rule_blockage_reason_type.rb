# frozen_string_literal: true

module Types
  module MergeRequests
    # rubocop: disable Graphql/AuthorizeTypes -- Only reachable through ApprovalRuleType, which authorizes
    class ApprovalRuleBlockageReasonType < BaseObject
      graphql_name 'ApprovalRuleBlockageReason'
      description 'Reason why an approval rule blocks a merge request.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :reason,
        type: ::Types::MergeRequests::ApprovalRuleBlockageReasonEnum,
        null: false,
        description: 'Kind of the reason.'

      field :coverage,
        type: GraphQL::Types::Float,
        null: true,
        description: 'Coverage of the head pipeline, in percent.'

      field :threshold,
        type: GraphQL::Types::Float,
        null: true,
        description: 'Minimum coverage threshold of the rule, in percent. Set only when `reason` is `BELOW_THRESHOLD`.'

      field :base_coverage,
        type: GraphQL::Types::Float,
        null: true,
        description: 'Coverage of the base pipeline, in percent. Set only when `reason` is `DECREASED`.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
