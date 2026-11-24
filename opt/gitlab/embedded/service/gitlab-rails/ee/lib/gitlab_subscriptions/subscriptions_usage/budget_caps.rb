# frozen_string_literal: true

module GitlabSubscriptions
  module SubscriptionsUsage
    class BudgetCaps
      include ::Gitlab::Utils::StrongMemoize

      UserOverride = Struct.new(
        :entity_id, :cap, :cap_enabled,
        :created_at, :updated_at,
        :declarative_policy_subject,
        keyword_init: true
      )

      def initialize(subscription_usage:)
        @subscription_usage = subscription_usage
      end

      def subscription_cap
        subscription_data[:subscriptionCap]
      end

      def subscription_cap_enabled
        subscription_data[:subscriptionCapEnabled]
      end

      def flat_user_cap
        subscription_data[:flatUserCap]
      end

      def flat_user_cap_enabled
        subscription_data[:flatUserCapEnabled]
      end

      def user_overrides(
        user_ids: nil, first: nil, last: nil,
        before: nil, after: nil
      )
        entity_ids = resolve_entity_ids(user_ids)
        args = { first: first, last: last,
                 before: before, after: after }.compact

        response = client.get_budget_caps(
          entity_ids: entity_ids, args: args
        )

        unless response[:success]
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
            StandardError.new("Failed to fetch user budget cap overrides"),
            response: response
          )

          return empty_page
        end

        data = response.dig(
          :budgetControls, :userBudgetCapOverrides
        ) || {}

        build_paginated_overrides(data)
      end

      def declarative_policy_subject
        subscription_usage
      end

      private

      attr_reader :subscription_usage

      def client
        subscription_usage.subscription_usage_client
      end

      def subscription_data
        response = client.get_budget_caps
        return {} unless response[:success]

        response.dig(:budgetControls, :subscription) || {}
      end
      strong_memoize_attr :subscription_data

      def resolve_entity_ids(user_ids)
        return if user_ids.blank?

        user_ids.map { |gid| gid.model_id.to_s }
      end

      def build_paginated_overrides(data)
        nodes = data[:nodes].to_a
        page_info = data[:pageInfo] || {}

        return empty_page if nodes.empty?

        overrides = nodes.map { |node| build_override(node) }

        Gitlab::Graphql::ExternallyPaginatedArray.new(
          page_info[:startCursor],
          page_info[:endCursor],
          *overrides,
          has_next_page: page_info[:hasNextPage],
          has_previous_page: page_info[:hasPreviousPage]
        )
      end

      def build_override(node)
        UserOverride.new(
          entity_id: node[:entityId],
          cap: node[:cap],
          cap_enabled: node[:capEnabled],
          created_at: node[:createdAt],
          updated_at: node[:updatedAt],
          declarative_policy_subject: subscription_usage
        )
      end

      def empty_page
        Gitlab::Graphql::ExternallyPaginatedArray.new(nil, nil)
      end
    end
  end
end
