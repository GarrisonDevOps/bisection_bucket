# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class DailyUsageType < BaseObject
        graphql_name 'GitlabSubscriptionDailyUsage'
        description 'Describes daily the usage of GitLab Credits'

        authorize :read_subscription_usage

        field :date,
          GraphQL::Types::ISO8601Date,
          null: false,
          description: 'Date when credits were used.'

        field :credits_used,
          GraphQL::Types::Float,
          null: false,
          description: 'GitLab Credits consumed on the date.'
      end
    end
  end
end
