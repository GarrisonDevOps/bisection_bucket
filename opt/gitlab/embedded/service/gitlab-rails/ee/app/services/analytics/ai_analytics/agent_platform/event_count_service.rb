# frozen_string_literal: true

module Analytics
  module AiAnalytics
    module AgentPlatform
      # rubocop: disable CodeReuse/ActiveRecord -- Not ActiveRecord
      class EventCountService
        include CommonUsageService
        include AiEventFields

        EVENT_NAME_TO_DB_FIELD_MAP = {
          created_session_event_count: :created_event_at,
          started_session_event_count: :started_event_at,
          finished_session_event_count: :finished_event_at,
          dropped_session_event_count: :dropped_event_at,
          stopped_session_event_count: :stopped_event_at,
          resumed_session_event_count: :resumed_event_at
        }.freeze

        FIELDS = EVENT_NAME_TO_DB_FIELD_MAP.keys.freeze

        def initialize(current_user, namespace:, from:, to:, fields: nil, **optional_parameters)
          @optional_params = optional_parameters || {}

          super(current_user, namespace: namespace, from: from, to: to, fields: fields)
        end

        private

        attr_reader :optional_params

        def usage_data
          ClickHouse::Client.select(query, :main).first
        end

        # Sample query output
        # when selecting encounter_duo_code_review_error_during_reviem
        # and find_no_issues_duo_code_review_after_review fields
        #
        #
        # WITH aggregated_sessions AS (
        #     SELECT
        #       anyIfMerge(created_event_at) AS created_event_at_value,
        #       anyIfMerge(started_event_at) AS started_event_at_value,
        #       anyIfMerge(finished_event_at) AS finished_event_at_value,
        #       anyIfMerge(dropped_event_at) AS dropped_event_at_value,
        #       anyIfMerge(stopped_event_at) AS stopped_event_at_value,
        #       anyIfMerge(resumed_event_at) AS resumed_event_at_value
        #     FROM agent_platform_sessions
        #     WHERE flow_type NOT IN ('chat')
        #     AND startsWith(namespace_path, '9970/')
        #     GROUP BY flow_type, user_id, session_id
        #     HAVING toDate(anyIfMerge(created_event_at)) >= '2024-11-27'
        #     AND toDate(anyIfMerge(created_event_at)) <= '2025-11-27'
        # )
        # SELECT
        #   countIf(isNotNull(created_event_at_value)) AS created_session_event_count,
        #   countIf(isNotNull(started_event_at_value)) AS started_session_event_count,
        #   countIf(isNotNull(finished_event_at_value)) AS finished_session_event_count,
        #   countIf(isNotNull(dropped_event_at_value)) AS dropped_session_event_count,
        #   countIf(isNotNull(stopped_event_at_value)) AS stopped_session_event_count,
        #   countIf(isNotNull(resumed_event_at_value)) AS resummed_session_event_count
        # FROM aggregated_sessions

        def query
          cte_query = build_cte_query

          cte_table = Arel::Table.new(:aggregated_sessions)
          cte = Arel::Nodes::As.new(cte_table, cte_query.to_arel)

          select_query = outer_query_for(cte_table)

          select_query_arel = select_query.to_arel
          select_from_cte = select_query_arel.with(cte)

          # Workaround to allow CTE queries with ClickHouse::Client::QueryBuilder
          select_query.instance_variable_set(:@manager, select_from_cte)

          select_query
        end

        def build_cte_query
          builder = ClickHouse::Client::QueryBuilder.new('agent_platform_sessions')

          inner_table = builder.table

          created_at_date =
            Arel::Nodes::NamedFunction.new('toDate', [
              Arel::Nodes::NamedFunction.new('anyIfMerge', [inner_table[:created_event_at]])
            ])

          select_fields =
            EVENT_NAME_TO_DB_FIELD_MAP.values.map do |event|
              Arel::Nodes::NamedFunction.new('anyIfMerge', [inner_table[event]]).as(event.to_s)
            end

          namespace_filter =
            Arel::Nodes::NamedFunction.new('startsWith',
              [Arel.sql('namespace_path'),
                Arel::Nodes.build_quoted(namespace.traversal_path(with_organization: false))])

          flow_types = optional_params[:flow_types]
          negated_flow_types = optional_params.dig(:not, :flow_types)

          builder = builder
            .select(*select_fields)
            .where(namespace_filter)
            .group(:flow_type, :user_id, :session_id)

          builder = builder.where(inner_table[:flow_type].in(flow_types)) if flow_types
          builder = builder.where(inner_table[:flow_type].not_in(negated_flow_types)) if negated_flow_types

          builder
            .having(created_at_date.gteq(from.to_date.iso8601))
            .having(created_at_date.lteq(to.to_date.iso8601))
        end

        # Builds the query that selects from CTE table
        def outer_query_for(cte_table)
          select_fields = field_expressions_for(cte_table)

          ClickHouse::Client::QueryBuilder.new(cte_table.name)
            .select(*select_fields)
        end

        def field_expressions_for(cte_table)
          EVENT_NAME_TO_DB_FIELD_MAP.filter_map do |field_name, db_name|
            next unless fields.include?(field_name)

            Arel::Nodes::NamedFunction.new(
              'countIf',
              [
                Arel::Nodes::NamedFunction.new(
                  'isNotNull',
                  [cte_table[db_name]]
                )
              ]
            ).as(field_name.to_s)
          end
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord -- Not ActiveRecord
    end
  end
end
