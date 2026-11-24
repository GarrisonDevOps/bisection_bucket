# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class SubscriptionUsageType < BaseObject
      graphql_name 'GitlabSubscriptionUsage'
      description 'Describes the usage of consumables under the subscription'

      authorize :read_subscription_usage

      field :enabled, GraphQL::Types::Boolean,
        null: false,
        method: :enabled?,
        description: 'Indicates if the Customer Portal GitLab Credits API is enabled.'

      field :is_outdated_client, GraphQL::Types::Boolean,
        null: true,
        method: :outdated_client?,
        description: 'Indicates if the GitLab instance has an outdated API contract with the Customer Portal.'

      field :last_event_transaction_at, GraphQL::Types::ISO8601DateTime,
        null: true,
        description: 'Date and time when the last usage event resulted in a wallet transaction.',
        deprecated: {
          reason: 'No longer supported',
          milestone: '19.6'
        }

      field :start_date, GraphQL::Types::ISO8601Date,
        null: true,
        description: 'Start date of the period covered by the usage data.'

      field :end_date, GraphQL::Types::ISO8601Date,
        null: true,
        description: 'End date of the period covered by the usage data.'

      field :purchase_credits_path, GraphQL::Types::String,
        null: true,
        description: 'URL to purchase GitLab Credits.',
        deprecated: {
          reason: 'No longer supported',
          milestone: '19.6'
        }

      field :credits_used, GraphQL::Types::Float,
        null: true,
        description: 'Total credits used for the subscription.'

      # rubocop: disable GraphQL/ExtractType -- no value for now
      field :daily_usage, [SubscriptionUsage::DailyUsageType],
        null: true,
        description: 'Daily usage for the subscription.' do
          argument :limit, GraphQL::Types::Int,
            required: false,
            description: 'Maximum number of daily usage entries to return. ' \
              'Defaults to every day in the date range.'
          argument :sort, SubscriptionUsage::DailyUsageSortEnum,
            required: false,
            description: 'Sort daily usage entries by the selected criteria.'
        end

      field :daily_average, GraphQL::Types::Float,
        null: true,
        description: 'Average daily credits used for the subscription.',
        deprecated: {
          reason: 'Divides by every day in the range, including days that have not happened yet. ' \
            'Compute the average from `creditsUsed` and the elapsed days of the range',
          milestone: '19.6'
        }

      field :monthly_waiver, SubscriptionUsage::MonthlyWaiverType,
        null: true,
        description: 'Monthly waiver usage for the subscription.',
        deprecated: {
          reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
            'Use `creditsUsed` and `dailyUsage`',
          milestone: '19.6'
        }

      field :monthly_commitment, SubscriptionUsage::MonthlyCommitmentType,
        null: true,
        description: 'Monthly commitment usage for the subscription.',
        deprecated: {
          reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
            'Use `creditsUsed` and `dailyUsage`',
          milestone: '19.6'
        }
      # rubocop:enable GraphQL/ExtractType

      field :products, [SubscriptionUsage::ProductType],
        null: true,
        description: 'All supported products with their associated flow types.'

      field :non_billable_usage, [SubscriptionUsage::NonBillableUsageType],
        null: true,
        description: 'GitLab Credits usage that was not billed, grouped by product and skip reason. ' \
          'Not included in `creditsUsed` or `dailyUsage`. Null when the usage cannot be read.'

      field :budget_caps, SubscriptionUsage::BudgetCapsType,
        null: true,
        description: 'Budget cap controls for the subscription.'

      field :overage, SubscriptionUsage::OverageType,
        null: true,
        description: 'Overage statistics.',
        deprecated: {
          reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
            'Use `creditsUsed` and `dailyUsage`',
          milestone: '19.6'
        }

      field :users_usage, SubscriptionUsage::UsersUsageType,
        null: true,
        description: 'Consumption usage for users under the subscription.'

      field :paid_tier_trial, SubscriptionUsage::PaidTierTrialType,
        null: false,
        description: 'Paid tier trial data for the subscription.',
        deprecated: {
          reason: 'Usage is reported for the entire subscription, not broken down by wallet. ' \
            'Use `creditsUsed` and `dailyUsage`',
          milestone: '19.6'
        }

      field :overage_terms_accepted, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether overage terms have been accepted for the subscription.',
        deprecated: {
          reason: 'No longer supported',
          milestone: '19.6'
        }

      field :can_accept_overage_terms, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether the subscription is currently eligible to accept overage terms.',
        deprecated: {
          reason: 'No longer supported',
          milestone: '19.6'
        }

      field :dap_promo_enabled, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether the Duo AI promo (DAP) is enabled for the subscription.',
        deprecated: {
          reason: 'No longer supported',
          milestone: '19.6'
        }

      field :subscription_portal_usage_dashboard_url, GraphQL::Types::String,
        null: true,
        description: 'Full URL to the GitLab Credits usage dashboard in the Customer Portal.',
        deprecated: {
          reason: 'No longer supported',
          milestone: '19.6'
        }

      def daily_usage(sort: :date_asc, limit: nil)
        object.daily_usage(sort: sort, limit: limit)
      end
    end
  end
end
