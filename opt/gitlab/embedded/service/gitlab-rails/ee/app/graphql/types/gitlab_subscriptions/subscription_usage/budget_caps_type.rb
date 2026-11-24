# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class BudgetCapsType < BaseObject
        graphql_name 'GitlabSubscriptionBudgetCaps'
        description 'Budget cap controls for a subscription.'

        authorize :read_subscription_usage

        # rubocop:disable GraphQL/ExtractType -- flat structure matches CDot API contract
        field :subscription_cap, GraphQL::Types::Float,
          null: true,
          description: 'Maximum budget cap for the subscription.'

        field :subscription_cap_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether the subscription-level budget cap is enabled.'

        field :flat_user_cap, GraphQL::Types::Float,
          null: true,
          description: 'Default per-user budget cap applied to all users.'

        field :flat_user_cap_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether the flat per-user budget cap is enabled.'
        # rubocop:enable GraphQL/ExtractType

        field :user_overrides,
          ::Types::GitlabSubscriptions::SubscriptionUsage::BudgetCaps::UserOverrideType
            .connection_type,
          connection_extension:
            Gitlab::Graphql::Extensions::
              ExternallyPaginatedArrayExtension,
          null: true,
          description: 'Per-user budget cap overrides. ' \
            'CDot returns a maximum of 20 overrides per page.' do
          argument :user_ids,
            [::Types::GlobalIDType[::User]],
            required: false,
            description: 'Filter overrides to specific users.'
        end
      end
    end
  end
end
