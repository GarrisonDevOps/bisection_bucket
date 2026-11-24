# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class MonthlyWaiverType < BaseObject
        graphql_name 'GitlabSubscriptionMonthlyWaiver'
        description 'GitLab Credits used from the Monthly Waiver allocation'

        authorize :read_subscription_usage

        field :total_credits,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Total of GitLab Credits allocated as Monthly Waiver.'

        field :credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'GitLab Credits used from the Monthly Waiver allocation.'

        field :daily_usage,
          [DailyUsageType],
          null: true,
          description: 'Array of daily usage of the Monthly Waiver allocation.'
      end
    end
  end
end
