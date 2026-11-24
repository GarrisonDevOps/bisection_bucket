# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    module User
      class CreditsUsageResolver < BaseResolver
        include ::GitlabSubscriptions::UsageRateLimitable

        type ::Types::GitlabSubscriptions::User::CreditsUsageType, null: true

        authorizes_object!
        authorize :read_user

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Path of the top-level namespace to report usage for.'

        argument :start_date, GraphQL::Types::ISO8601Date,
          required: false,
          description: 'Start date of the usage period to query. Defaults to the beginning of the current month.'

        argument :end_date, GraphQL::Types::ISO8601Date,
          required: false,
          description: 'End date of the usage period to query. Defaults to the end of the current month.'

        argument :flow_types, [GraphQL::Types::String],
          required: false,
          description: 'Filter usage data by flow type identifiers (for example, ["chat", "code_review"]).'

        MAX_DATE_RANGE = 1.year

        CREDITS_USAGE_RATE_LIMIT_KEYS = %i[
          credits_usage_per_minute
          credits_usage_per_hour
          credits_usage_per_day
        ].freeze

        def resolve(**args)
          start_date = args[:start_date] || Date.current.beginning_of_month
          end_date = args[:end_date] || Date.current.end_of_month

          validate_date_range!(start_date, end_date)

          namespace = find_namespace(args[:namespace_path])

          authorize!(namespace)
          check_usage_rate_limit!(namespace)

          effective_start = clamp_start_date(start_date, namespace)
          effective_end = [end_date, Date.current].min

          ::GitlabSubscriptions::SubscriptionsUsage::User::CreditsUsage.new(
            user: object,
            namespace: namespace,
            subscription_usage_client: subscription_usage_client(namespace, effective_start, effective_end),
            flow_types: args[:flow_types].presence
          )
        end

        private

        def subscription_usage_client(namespace, start_date, end_date)
          client_arguments = { namespace_id: namespace.id, start_date: start_date.iso8601, end_date: end_date.iso8601 }
          clients = context[:credits_usage_subscription_usage_clients] ||= {}

          clients[client_arguments] ||=
            ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new(**client_arguments)
        end

        def usage_rate_limit_keys
          CREDITS_USAGE_RATE_LIMIT_KEYS
        end

        def usage_rate_limit_enforced?(namespace)
          ::Feature.enabled?(:enforce_credits_usage_rate_limits, namespace, type: :gitlab_com_derisk)
        end

        def usage_rate_limit_log_message
          'Credits usage rate limit exceeded'
        end

        def authorize!(namespace)
          raise_resource_not_available_error! unless object == current_user
          raise_resource_not_available_error! unless current_user.human?
          raise_resource_not_available_error! unless namespace
          raise_resource_not_available_error! unless namespace.root? && namespace.group_namespace?
          raise_resource_not_available_error! unless namespace.gitlab_credits_entitled?
          raise_resource_not_available_error! unless namespace.member_of_self_or_descendant?(current_user)
        end

        def validate_date_range!(start_date, end_date)
          if end_date < start_date
            raise Gitlab::Graphql::Errors::ArgumentError,
              "end_date must be after or equal to start_date"
          end

          return unless end_date > start_date + MAX_DATE_RANGE

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Date range cannot exceed 1 year"
        end

        def find_namespace(namespace_path)
          Namespace.find_by_full_path(namespace_path)
        end

        def clamp_start_date(start_date, namespace)
          subscription_start = namespace.gitlab_subscription&.start_date

          return start_date unless subscription_start

          [start_date, subscription_start].max
        end
      end
    end
  end
end
