# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class SubscriptionHistoryChangeTypeEnum < BaseEnum
      graphql_name 'SubscriptionHistoryChangeType'
      description 'Types of change for a subscription history record'

      value 'GITLAB_SUBSCRIPTION_UPDATED',
        value: 'gitlab_subscription_updated',
        description: 'This was the previous state before the subscription was updated.'

      value 'GITLAB_SUBSCRIPTION_DESTROYED',
        value: 'gitlab_subscription_destroyed',
        description: 'This was the previous state before the subscription was destroyed.'
    end
  end
end
