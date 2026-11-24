# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class UsersUsageType < BaseObject
        graphql_name 'GitlabSubscriptionUsageUsersUsage'
        description 'Describes the usage of consumables by users under the subscription'

        authorize :read_subscription_usage

        # rubocop: disable GraphQL/ExtractType -- no value for now
        field :total_active_users, GraphQL::Types::Int,
          null: true,
          description: 'Total number of users with usage in the subscription.'

        field :total_users_using_credits, GraphQL::Types::Int,
          null: true,
          description: 'Total number of users consuming GitLab Credits from their included allocation.',
          deprecated: {
            reason: 'No longer supported',
            milestone: '19.6'
          }

        field :total_users_using_monthly_commitment, GraphQL::Types::Int,
          null: true,
          description: 'Total number of users consuming GitLab Credits from the subscription monthly commitment.',
          deprecated: {
            reason: 'No longer supported',
            milestone: '19.6'
          }

        field :total_users_using_overage, GraphQL::Types::Int,
          null: true,
          description: 'Total number of users consuming overage.',
          deprecated: {
            reason: 'No longer supported',
            milestone: '19.6'
          }
        # rubocop:enable GraphQL/ExtractType

        field :credits_used, GraphQL::Types::Float,
          null: true,
          description: 'GitLab Credits used by consumers of the subscription.',
          deprecated: {
            reason: 'Use `creditsUsed` on `GitlabSubscriptionUsage`',
            milestone: '19.6'
          }

        field :daily_usage,
          [DailyUsageType],
          null: true,
          description: 'Array of daily usage of GitLab Credits.',
          deprecated: {
            reason: 'Use `dailyUsage` on `GitlabSubscriptionUsage`',
            milestone: '19.6'
          }

        field :users, UserType.connection_type,
          connection_extension: Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
          null: true,
          max_page_size: ::GitlabSubscriptions::SubscriptionsUsage::UserUsage::MAX_USERS_PER_PAGE,
          description: 'List of users with their usage data.' do
          argument :search_query, GraphQL::Types::String,
            required: false,
            description: 'Filter users with a matching name, username, or email. Ignored when username is provided ' \
              'or when sorting by total credits used.'
          argument :sort, UserSortEnum,
            required: false,
            description: 'Sort users by the criteria.'
          argument :username, GraphQL::Types::String,
            required: false,
            description: 'Username of the User.'
        end

        def total_active_users
          object.total_active_users(flow_types: context[:flow_types])
        end

        def users(search_query: nil, sort: nil, username: nil, first: nil, last: nil, after: nil, before: nil)
          object.users(
            search_query: search_query,
            sort: sort,
            username: username,
            first: first,
            last: last,
            after: after,
            before: before,
            flow_types: context[:flow_types]
          )
        end
      end
    end
  end
end
