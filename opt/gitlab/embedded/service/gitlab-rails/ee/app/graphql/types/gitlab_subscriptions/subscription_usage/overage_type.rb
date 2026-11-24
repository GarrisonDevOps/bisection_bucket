# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class OverageType < BaseObject
        graphql_name 'GitlabSubscriptionOverage'
        description 'Describes the overage of consumables for the subscription'

        authorize :read_subscription_usage

        field :is_allowed,
          GraphQL::Types::Boolean,
          null: true,
          description: 'Whether GitLab Credits overage is allowed for the subscription.'

        field :credits_used,
          GraphQL::Types::Float,
          null: true,
          description: 'Overage consumed by the subscription.'

        field :daily_usage,
          [DailyUsageType],
          null: true,
          description: 'Array of daily overage usage.'
      end
    end
  end
end
