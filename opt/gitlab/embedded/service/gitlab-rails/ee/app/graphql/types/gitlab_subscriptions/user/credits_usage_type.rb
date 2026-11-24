# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module User
      class CreditsUsageType < BaseObject
        graphql_name 'GitlabSubscriptionUserCreditsUsage'
        description 'GitLab Credits usage for the current user'

        authorize_granular_token parent_authorizes: :read_user

        authorize :read_user

        field :enabled, GraphQL::Types::Boolean,
          null: false,
          method: :enabled?,
          description: 'Indicates if the Customer Portal GitLab Credits API is enabled.'

        field :is_outdated_client, GraphQL::Types::Boolean,
          null: true,
          method: :outdated_client?,
          description: 'Indicates if the GitLab instance has an outdated API contract with the Customer Portal.'

        field :start_date, GraphQL::Types::ISO8601Date,
          null: true,
          description: 'Start date of the period covered by the usage data.'

        field :end_date, GraphQL::Types::ISO8601Date,
          null: true,
          description: 'End date of the period covered by the usage data.'

        field :credits_used, GraphQL::Types::Float,
          null: true,
          description: 'Total GitLab Credits consumed by the current user.'

        field :daily_usage, [DailyUsageType],
          null: true,
          description: 'Daily GitLab Credits usage for the current user.'

        field :non_billable_usage, [NonBillableUsageType],
          null: true,
          description: 'GitLab Credits usage by the current user that was not billed, grouped by product and ' \
            'skip reason. Not included in `creditsUsed` or `dailyUsage`. Null when the usage cannot be read.'

        field :products, [ProductType],
          null: true,
          description: 'All supported products with their associated flow types.'

        field :used_flow_types, [SubscriptionUsage::FlowTypeInfoType],
          null: true,
          description: 'Flow types the current user consumed credits under during the period.',
          deprecated: {
            reason: 'No longer supported',
            milestone: '19.6'
          }

        field :blocked_status, SubscriptionUsage::BlockedStatusType,
          null: true,
          description: 'Blocked status of the current user under the subscription budget cap.'
      end
    end
  end
end
