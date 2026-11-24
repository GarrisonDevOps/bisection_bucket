# frozen_string_literal: true

module Analytics
  module AiAnalytics
    class AiUserMetricsService
      ALL_FEATURES = :all_features

      # rubocop: disable CodeReuse/ActiveRecord -- no ActiveRecord
      def initialize(current_user:, namespace:, from:, to:, feature:, sort: nil, user_ids: nil)
        @namespace = namespace
        @from = from
        @to = to
        @feature = feature
        @sort = sort
        @current_user = current_user
        @user_ids = user_ids
      end

      def execute
        return clickhouse_unavailable_error unless Gitlab::ClickHouse.enabled_for_analytics?(namespace)

        builder = ClickHouse::Client::QueryBuilder.new('ai_usage_events_daily')
        query = if feature_events.present?
                  build_unified_query(builder)
                else
                  builder.none
                end

        ServiceResponse.success(payload: query)
      end

      private

      attr_reader :current_user, :namespace, :from, :to, :feature, :sort, :user_ids

      def fetch_all_features?
        feature == ALL_FEATURES
      end

      def build_unified_query(builder)
        query = builder
          .select(builder.table[:user_id])
          .then { |q| add_total_events_count(q, builder) }
          .then { |q| add_event_aggregations(q, builder) }
          .then { |q| apply_common_filters(q, builder) }
          .group(:user_id)

        query = apply_sorting(query, builder) if sort.present?
        query.order(:user_id, :asc)
      end

      def add_total_events_count(query, builder)
        total_count_expression = Arel::Nodes::NamedFunction.new('sumIf', [
          Arel.sql('occurrences'),
          builder.table[:event].in(feature_event_ids)
        ]).as('total_events_count')

        query.select(total_count_expression)
      end

      def add_event_aggregations(query, builder)
        feature_event_ids.each do |event_id|
          event_name = event_name_from_id(event_id)
          count_expression = Arel::Nodes::NamedFunction.new('sumIf', [
            Arel.sql('occurrences'),
            builder.table[:event].eq(event_id)
          ]).as("#{event_name}_event_count")

          query = query.select(count_expression)
        end

        last_activity_expression = Arel::Nodes::NamedFunction.new('nullIf', [
          Arel::Nodes::NamedFunction.new('maxIf', [
            builder.table[:date],
            builder.table[:event].in(feature_event_ids)
          ]),
          Arel.sql("toDate32('1970-01-01')")
        ]).as('last_duo_activity_on')

        query.select(last_activity_expression)
      end

      def apply_sorting(query, builder)
        column_name, expression = sort_column(builder)
        query = query.select(expression.as(column_name)) if expression
        query.order(Arel.sql(column_name), sort[:direction])
      end

      def sort_column(builder)
        sort_field = sort[:field]

        if sort_field == :total_events_count
          ['total_events_count', nil]
        elsif ::Ai::UsageEvent.events[sort_field].present?
          event_id = ::Ai::UsageEvent.events[sort_field]

          if feature_event_ids.include?(event_id)
            ["#{event_name_from_id(event_id)}_event_count", nil]
          else
            expression = builder.func('sumIf', [
              Arel.sql('occurrences'),
              builder.table[:event].eq(event_id)
            ])

            ['sort_expr', expression]
          end
        else
          expression = builder.func('sumIf', [
            Arel.sql('occurrences'),
            builder.table[:event].in(event_ids_for_feature(sort_field))
          ])

          ['sort_expr', expression]
        end
      end

      def apply_common_filters(query, builder)
        query = date_range_condition(query, builder)
        apply_optional_filters(query, builder)
      end

      def apply_optional_filters(query, builder)
        query = filter_by_namespace(query, builder) if namespace_filtering_enabled?
        query = filter_by_user_ids(query, builder) if user_ids.present?
        query
      end

      def event_ids_for_feature(feature_name)
        return feature_event_ids if feature_name == feature

        ::Gitlab::Tracking::AiTracking.registered_user_action_events(feature_name).values
      end

      def date_range_condition(query, builder)
        formatted_from = from.to_date.iso8601
        formatted_to = to.to_date.iso8601

        query.where(builder.table[:date].gteq(formatted_from))
             .where(builder.table[:date].lteq(formatted_to))
      end

      def feature_events
        @feature_events ||= registered_event_names
      end

      def feature_event_ids
        @feature_event_ids ||= registered_event_names.filter_map do |name|
          ::Ai::UsageEvent.events[name]
        end.compact
      end

      def registered_event_names
        if fetch_all_features?
          Gitlab::Tracking::AiTracking.registered_features.flat_map do |feature|
            ::Gitlab::Tracking::AiTracking.registered_user_action_events(feature).keys
          end
        else
          ::Gitlab::Tracking::AiTracking.registered_user_action_events(feature).keys
        end
      end

      def filter_by_namespace(query, builder)
        namespace_path_condition = Arel::Nodes::NamedFunction.new('startsWith', [
          builder.table[:namespace_path],
          Arel::Nodes.build_quoted(namespace.traversal_path(with_organization: false).to_s)
        ])

        query.where(namespace_path_condition)
      end

      def filter_by_user_ids(query, builder)
        query.where(builder.table[:user_id].in(user_ids))
      end

      def event_name_from_id(event_id)
        ::Ai::UsageEvent.events.key(event_id)
      end

      def namespace_filtering_enabled?
        return Feature.enabled?(:use_duo_chat_namespace_path_filter, namespace) if feature.to_sym == :chat

        true
      end

      def clickhouse_unavailable_error
        ServiceResponse.error(
          message: s_('AiAnalytics|the ClickHouse data store is not available')
        )
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
