# frozen_string_literal: true

module GitlabSubscriptions
  module SubscriptionsUsage
    module User
      class CreditsUsage
        include ::Gitlab::Utils::StrongMemoize

        BlockedStatus = Struct.new(:blocked, :cap_type, :declarative_policy_subject, keyword_init: true)

        def initialize(user:, namespace:, subscription_usage_client:, flow_types: nil)
          @user = user
          @namespace = namespace
          @subscription_usage_client = subscription_usage_client
          @flow_types = flow_types
        end

        attr_reader :user, :namespace, :subscription_usage_client, :flow_types

        def enabled?
          !!usage_metadata[:enabled]
        end

        def outdated_client?
          usage_metadata[:isOutdatedClient]
        end

        def start_date
          usage_metadata[:startDate]
        end

        def end_date
          usage_metadata[:endDate]
        end

        def credits_used
          user_usage[:totalCreditsUsed]
        end

        def daily_usage
          response = subscription_usage_client.get_daily_usage_for_user_id(user.id, flow_types: flow_types)
          return [] unless response[:success]

          build_daily_usage(response[:dailyUsage])
        end
        strong_memoize_attr :daily_usage

        def non_billable_usage
          response = subscription_usage_client.get_non_billable_usage_for_user_id(user.id, flow_types: flow_types)
          return unless response[:success]

          response[:nonBillableUsage].to_a.map do |usage|
            ::GitlabSubscriptions::SubscriptionUsage::NonBillableUsage.new(
              product_id: usage[:productId],
              skip_reason: usage[:skipReason],
              total_credits_used: usage[:totalCreditsUsed],
              daily_usage: build_daily_usage(usage[:dailyUsage]),
              declarative_policy_subject: declarative_policy_subject
            )
          end
        end
        strong_memoize_attr :non_billable_usage

        def used_flow_types
          response = subscription_usage_client.get_used_flow_types_for_user_id(user.id)
          return [] unless response[:success]

          response[:usedFlowTypes].to_a.map do |flow_type|
            ::GitlabSubscriptions::SubscriptionUsage::ProductFlowType.new(
              id: flow_type[:id],
              title: flow_type[:title],
              declarative_policy_subject: declarative_policy_subject
            )
          end
        end
        strong_memoize_attr :used_flow_types

        def products
          response = subscription_usage_client.get_products
          return [] unless response[:success]

          response[:products].to_a.map do |product|
            ::GitlabSubscriptions::SubscriptionUsage::Product.new(
              id: product[:id],
              title: product[:title],
              # Deliberately omitted: subscription-wide figure, not this user's.
              credits_used: nil,
              flow_types: build_product_flow_types(product[:flowTypes]),
              declarative_policy_subject: declarative_policy_subject
            )
          end
        end
        strong_memoize_attr :products

        def blocked_status
          response = subscription_usage_client.get_blocked_statuses([user.id.to_s])
          return unless response[:success]

          status = response[:blockedStatuses].to_a.find { |s| s[:entityId].to_i == user.id }
          return unless status

          BlockedStatus.new(
            blocked: status[:blocked],
            cap_type: status[:capType],
            declarative_policy_subject: declarative_policy_subject
          )
        end
        strong_memoize_attr :blocked_status

        def declarative_policy_subject
          user
        end

        private

        def build_daily_usage(daily_usage)
          daily_usage.to_a.map do |usage|
            ::GitlabSubscriptions::SubscriptionUsage::DailyUsage.new(
              date: usage[:date],
              credits_used: usage[:creditsUsed],
              declarative_policy_subject: declarative_policy_subject
            )
          end
        end

        def build_product_flow_types(flow_types)
          flow_types.to_a.map do |flow_type|
            ::GitlabSubscriptions::SubscriptionUsage::ProductFlowType.new(
              id: flow_type[:id],
              title: flow_type[:title],
              declarative_policy_subject: declarative_policy_subject
            )
          end
        end

        def user_usage
          response = subscription_usage_client.get_usage_for_user_ids([user.id], flow_types: flow_types)
          return {} unless response[:success]

          response[:usersUsage].to_a.find { |usage| usage[:userId] == user.id } || {}
        end
        strong_memoize_attr :user_usage

        def usage_metadata
          subscription_usage_client.get_metadata[:subscriptionUsage] || {}
        end
        strong_memoize_attr :usage_metadata
      end
    end
  end
end
