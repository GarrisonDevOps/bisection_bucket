# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class TrialUsageType < BaseObject
      graphql_name 'GitlabTrialUsage'
      description 'Describes the usage and details of a trial subscription'

      authorize :read_subscription_usage

      field :active_trial, SubscriptionUsage::ActiveTrialType,
        null: true,
        description: 'Active trial information if the subscription has an active trial.'

      field :users_usage, SubscriptionUsage::TrialUsageType,
        null: true,
        method: :trial_users_usage,
        description: 'Trial usage statistics for users.'
    end
  end
end
