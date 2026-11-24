# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module User
      # Similar to SubscriptionUsage::DailyUsageType but authorizes `read_user`
      class DailyUsageType < BaseObject
        graphql_name 'GitlabSubscriptionUserCreditsUsageDailyUsage'
        description 'Daily GitLab Credits usage for the current user.'

        authorize_granular_token skip_reason: :parent_authorizes

        authorize :read_user

        field :date, GraphQL::Types::ISO8601Date, null: false,
          description: 'Date when credits were used.'

        field :credits_used, GraphQL::Types::Float, null: false,
          description: 'GitLab Credits consumed by the current user on the date.'
      end
    end
  end
end
