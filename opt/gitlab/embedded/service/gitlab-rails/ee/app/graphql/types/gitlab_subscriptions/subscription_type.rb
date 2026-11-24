# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class SubscriptionType < BaseObject
      graphql_name 'GitlabSubscription'
      description 'GitLab.com subscription of a namespace.'

      authorize :read_gitlab_subscription
      authorize_granular_token permissions: :read_gitlab_subscription, boundary: :namespace, boundary_type: :group

      field :active, GraphQL::Types::Boolean,
        null: false,
        method: :active_paid_or_trial?,
        description: 'Indicates the subscription is on a paid or trial plan that has not expired.'
    end
  end
end
