# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module User
      # Similar to SubscriptionUsage::NonBillableUsageType but authorizes `read_user`
      class NonBillableUsageType < BaseObject
        graphql_name 'GitlabSubscriptionUserCreditsUsageNonBillableUsage'
        description 'GitLab Credits usage by the current user that was not billed, for one product and skip reason.'

        authorize_granular_token skip_reason: :parent_authorizes

        authorize :read_user

        field :product_id, GraphQL::Types::String, null: false,
          description: 'Identifier of the product the usage belongs to. ' \
            'Matches `GitlabSubscriptionUserCreditsUsageProduct.id`.'

        field :skip_reason, GraphQL::Types::String, null: true,
          description: 'Reason the usage was not billed, as recorded on the usage event. ' \
            'Null when the event has no recorded reason.'

        field :total_credits_used, GraphQL::Types::Float, null: false,
          description: 'Total non-billable GitLab Credits of the current user for the product and skip reason ' \
            'in the date range.'

        field :daily_usage, [DailyUsageType], null: false,
          description: 'Daily non-billable GitLab Credits of the current user for the product and skip reason.'
      end
    end
  end
end
