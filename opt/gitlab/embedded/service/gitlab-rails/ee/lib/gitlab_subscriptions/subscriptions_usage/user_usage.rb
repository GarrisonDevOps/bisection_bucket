# frozen_string_literal: true

module GitlabSubscriptions
  module SubscriptionsUsage
    class UserUsage
      include ::Gitlab::Utils::StrongMemoize

      MAX_USERS_PER_PAGE = 20

      def initialize(subscription_usage:)
        @subscription_usage = subscription_usage
      end

      def daily_usage
        usage_stats[:dailyUsage].to_a.map do |usage|
          GitlabSubscriptions::SubscriptionUsage::DailyUsage.new(
            date: usage[:date],
            credits_used: usage[:creditsUsed],
            declarative_policy_subject: declarative_policy_subject
          )
        end
      end
      strong_memoize_attr :daily_usage

      def total_active_users(flow_types: nil)
        usage_stats(flow_types: flow_types.presence)[:totalActiveUsers]
      end

      def total_users_using_credits
        usage_stats[:totalUsersUsingCredits]
      end

      def total_users_using_monthly_commitment
        usage_stats[:totalUsersUsingMonthlyCommitment]
      end

      def total_users_using_overage
        usage_stats[:totalUsersUsingOverage]
      end

      def credits_used
        usage_stats[:creditsUsed]
      end

      def users(
        search_query: nil, sort: nil, username: nil, first: nil, last: nil, before: nil, after: nil,
        flow_types: nil)
        strong_memoize_with(:users, search_query, sort, username, first, last, before, after, flow_types) do
          if username.blank? && sort.in?([:total_credits_used_asc, :total_credits_used_desc])
            if search_query.present?
              raise Gitlab::Graphql::Errors::ArgumentError,
                '`searchQuery` not supported when sorting by total credits used'
            end

            users_sorted_by_credits_used({
              sort: sort, first: first, last: last, before: before, after: after, flow_types: flow_types
            })

          else
            users = case subscription_usage.subscription_target
                    when :namespace
                      namespace_users = users_in_subscription

                      username.present? ? namespace_users.by_username(username) : namespace_users
                    when :instance
                      username.present? ? ::User.by_username(username) : ::User.all
                    end&.human_or_service_user

            next users if username.present?

            users = searched_users(users, search_query)

            sorted_users(users, sort)
          end
        end
      end

      def declarative_policy_subject
        subscription_usage
      end

      private

      attr_reader :subscription_usage

      def usage_stats(flow_types: nil)
        strong_memoize_with(:usage_stats, flow_types) do
          subscription_usage.subscription_usage_client
            .get_users_usage_stats(flow_types: flow_types)[:usersUsage] || {}
        end
      end

      def get_consumers(args = {})
        strong_memoize_with(:get_consumers, args) do
          subscription_usage.subscription_usage_client.get_consumers(args)[:consumers] || {}
        end
      end

      def users_in_scope
        case subscription_usage.subscription_target
        when :namespace
          users_in_subscription
        else
          ::User.all
        end
      end

      # An Organization's usage covers all its users, not only the nominated group's members.
      def users_in_subscription
        organization = subscription_usage.organization
        return organization.users.without_order if organization

        users_from_descendant_members
      end

      def users_from_descendant_members
        namespace = subscription_usage.namespace
        user_ids = Member.from_union(
          [
            namespace.descendant_project_members_with_inactive.select(:user_id),
            namespace.members_with_descendants.select(:user_id)
          ],
          remove_duplicates: true
        ).select(:user_id)

        ::User.id_in(user_ids).without_order
      end

      def searched_users(users, search_query)
        return users if search_query.blank?

        users.search(
          search_query,
          with_private_emails: true,
          partial_email_search: !::Gitlab::Saas.feature_available?(:disable_partial_email_search)
        )
      end

      def sorted_users(users, sort)
        return users if users.nil? || sort.blank?

        users.sort_by_attribute(sort)
      end

      def users_sorted_by_credits_used(args)
        consumers = get_consumers(args)
        nodes = consumers[:nodes].to_a
        page_info = consumers[:pageInfo] || {}

        return Gitlab::Graphql::ExternallyPaginatedArray.new(nil, nil) if nodes.empty?

        user_ids = nodes.pluck(:userId) # rubocop:disable CodeReuse/ActiveRecord -- this is an array from a GraphQL response, not an ActiveRecord query

        users = users_in_scope.by_ids(user_ids).non_internal.limit(MAX_USERS_PER_PAGE)

        users_by_id = users.index_by(&:id)
        consumers_by_user_id = nodes.index_by { |node| node[:userId] }

        sorted_users = user_ids.filter_map do |user_id|
          user = users_by_id[user_id]
          consumer = consumers_by_user_id[user_id]
          next unless user
          next unless consumer[:totalCreditsUsed].to_f + consumer[:nonBillableCreditsUsed].to_f > 0

          ::GitlabSubscriptions::SubscriptionsUsage::UserWithConsumption.new(user, consumer)
        end

        Gitlab::Graphql::ExternallyPaginatedArray.new(
          page_info[:startCursor],
          page_info[:endCursor],
          *sorted_users,
          has_next_page: page_info[:hasNextPage],
          has_previous_page: page_info[:hasPreviousPage]
        )
      end
    end
  end
end
