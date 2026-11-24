# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class UserUsageType < BaseObject
        graphql_name 'GitlabSubscriptionUsageUserUsage'
        description 'Describes the usage of consumables for a user under the subscription'

        authorize :read_user

        field :credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'GitLab Credits used by the user.',
          deprecated: {
            reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
              'Use `totalCreditsUsed`',
            milestone: '19.6'
          }
        # rubocop: disable GraphQL/ExtractType -- different types of usage that start with monthly_
        field :monthly_commitment_credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Monthly Commitment GitLab Credits used by the user.',
          deprecated: {
            reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
              'Use `totalCreditsUsed`',
            milestone: '19.6'
          }
        field :monthly_waiver_credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Monthly Waiver GitLab Credits used by the user.',
          deprecated: {
            reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
              'Use `totalCreditsUsed`',
            milestone: '19.6'
          }
        # rubocop: enable GraphQL/ExtractType
        field :overage_credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Overage GitLab Credits used by the user.',
          deprecated: {
            reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
              'Use `totalCreditsUsed`',
            milestone: '19.6'
          }
        field :paid_tier_trial_credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Paid Tier Trial GitLab Credits used by the user.',
          deprecated: {
            reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
              'Use `totalCreditsUsed`',
            milestone: '19.6'
          }
        # rubocop: disable GraphQL/ExtractType -- these are different totals
        field :total_credits,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Total GitLab Credits available for the user.',
          deprecated: {
            reason: 'No longer supported',
            milestone: '19.6'
          }
        field :total_credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Total GitLab Credits used by the user across all wallets.'
        # rubocop: enable GraphQL/ExtractType
        field :non_billable_credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'GitLab Credits used by the user that were not billed. ' \
            'Not included in `creditsUsed` or `totalCreditsUsed`. Null when the usage cannot be read.'
      end
    end
  end
end
