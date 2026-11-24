# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class TrialUsageType < BaseObject
        graphql_name 'TrialUsage'
        description 'Trial usage statistics'

        authorize :read_subscription_usage

        field :credits_used, GraphQL::Types::Float,
          null: true,
          description: 'Total credits used during a trial.'

        field :total_users_using_credits, GraphQL::Types::Int,
          null: true,
          description: 'Number of users who have used credits during a trial.'

        field :users, Types::GitlabSubscriptions::TrialUsage::UserType.connection_type,
          null: true,
          max_page_size: 20,
          description: 'List of users with their trial usage data.' do
            argument :username, GraphQL::Types::String,
              required: false,
              description: 'Username of the User.'
          end

        def users(username: nil)
          object.users(username: username)
        end
      end
    end
  end
end
