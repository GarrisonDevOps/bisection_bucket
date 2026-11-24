# frozen_string_literal: true

module Resolvers
  module Govern
    class PolicyEvaluationsResolver < BaseResolver
      include LooksAhead

      authorize_granular_token permissions: :read_govern_policy,
        boundaries: [
          { boundary: :itself, boundary_type: :group },
          { boundary: :itself, boundary_type: :project },
          { boundary: :instance, boundary_type: :instance }
        ]

      type ::Types::Govern::PolicyEvaluationType.connection_type, null: true

      # Each node carries its violations as an unpaginated list, so a page costs
      # evaluations times violations. Halving the schema default halves the common
      # case; it does not bound the product, because nothing caps violations yet.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/630210.
      max_page_size 50

      argument :policy_id, GraphQL::Types::Int,
        required: false,
        experiment: { milestone: '19.4' },
        description: 'Return only the evaluations of the policy with the given ID.'

      argument :mode, ::Types::Govern::PolicyEvaluationModeEnum,
        required: false,
        experiment: { milestone: '19.4' },
        description: 'Return only the evaluations that ran in the given enforcement mode.'

      argument :verdict, ::Types::Govern::PolicyEvaluationVerdictEnum,
        required: false,
        experiment: { milestone: '19.4' },
        description: 'Return only the evaluations that produced the given verdict.'

      argument :evaluated_after, Types::TimeType,
        required: false,
        experiment: { milestone: '19.4' },
        description: 'Return only the evaluations that ran at or after the given timestamp.'

      argument :evaluated_before, Types::TimeType,
        required: false,
        experiment: { milestone: '19.4' },
        description: 'Return only the evaluations that ran at or before the given timestamp.'

      def resolve_with_lookahead(**args)
        evaluations = ::Govern::PolicyEvaluationsFinder.new(container: object, params: args).execute

        apply_lookahead(evaluations)
      end

      private

      def preloads
        { violations: [:violations] }
      end
    end
  end
end
