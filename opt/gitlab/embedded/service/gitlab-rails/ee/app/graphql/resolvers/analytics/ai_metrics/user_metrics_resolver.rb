# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class UserMetricsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type ::Types::Analytics::AiMetrics::UserMetricsType, null: true

        authorizes_object!
        authorize :read_enterprise_ai_analytics

        ALL_FEATURES = ::Analytics::AiAnalytics::AiUserMetricsService::ALL_FEATURES

        argument :start_date, Types::DateType,
          required: false,
          description: 'Date range to start from. Default is the beginning of current month.
           ClickHouse needs to be enabled when passing this param.'

        argument :end_date, Types::DateType,
          required: false,
          description: 'Date range to end at. Default is the end of current month.
           ClickHouse needs to be enabled when passing this param.'

        argument :sort, Types::Analytics::AiMetrics::UserMetricsSortEnum,
          required: false,
          description: 'Sort AI user metrics.'

        def ready?(**args)
          validate_params!(args)

          super
        end

        def resolve(**args)
          context[:ai_metrics_params] =
            params_with_defaults(args).merge(namespace: namespace)

          result = ::Analytics::AiAnalytics::AiUserMetricsService.new(
            current_user: current_user,
            namespace: namespace,
            from: context[:ai_metrics_params][:start_date],
            to: context[:ai_metrics_params][:end_date],
            feature: first_registered_feature, # feature type doesn't matter for sorting
            sort: context[:ai_metrics_params][:sort]
          ).execute

          return [] unless result.success?

          Gitlab::Graphql::Pagination::ClickHouseAggregatedRelation.new(
            result.payload,
            context_attributes: { namespace: namespace }
          )
        end

        private

        def first_registered_feature
          return ALL_FEATURES if context[:ai_metrics_params][:sort].nil?

          sort_field = context[:ai_metrics_params][:sort][:field]

          return ALL_FEATURES if total_events_sort?(sort_field)

          Gitlab::Tracking::AiTracking.registered_features.first
        end

        def total_events_sort?(sort_field)
          sort_field == :total_events_count
        end

        def validate_params!(args)
          params = params_with_defaults(args)

          return unless params[:start_date] < params[:end_date] - 1.year

          raise Gitlab::Graphql::Errors::ArgumentError, 'maximum date range is 1 year'
        end

        def params_with_defaults(args)
          { start_date: Time.current.beginning_of_month, end_date: Time.current.end_of_month }.merge(args)
        end

        def namespace
          object.try(:project_namespace) || object
        end
      end
    end
  end
end
