# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class MonthlyCommitmentType < BaseObject
        graphql_name 'GitlabSubscriptionMonthlyCommitment'
        description "Describes the usage of GitLab Credits for the subscription's monthly commitment"

        authorize :read_subscription_usage

        field :total_credits,
          type: GraphQL::Types::Float,
          null: true,
          description: "Total of GitLab Credits allocated as a subscription's monthly commitment."

        field :credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: "Total of GitLab Credits consumed from the subscription's monthly commitment."

        field :daily_usage,
          [DailyUsageType],
          null: true,
          description: "Array of daily usage of the subscription's monthly commitment."
      end
    end
  end
end
