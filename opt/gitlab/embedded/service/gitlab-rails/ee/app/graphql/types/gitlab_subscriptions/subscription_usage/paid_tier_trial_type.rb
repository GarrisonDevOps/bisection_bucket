# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class PaidTierTrialType < BaseObject
        graphql_name 'GitlabSubscriptionPaidTierTrial'
        description 'Describes paid tier trial information for the subscription'

        authorize :read_subscription_usage

        field :is_active,
          type: GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether the subscription is currently in a paid tier trial for GitLab Credits.'

        field :daily_usage,
          [DailyUsageType],
          null: true,
          description: "Array of daily usage of the subscription's paid tier trial."
      end
    end
  end
end
