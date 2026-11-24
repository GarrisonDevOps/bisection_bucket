# frozen_string_literal: true

module Analytics
  module AiAnalytics
    module AgentPlatform
      # rubocop: disable CodeReuse/ActiveRecord -- Not ActiveRecord
      class FlowMetricsService
        include CommonUsageService

        FIELDS =
          %i[flow_type sessions_count median_execution_time users_count completion_rate].freeze

        SORTING_FIELDS_MAP = {
          sessions_count_asc: ['sessions_count', :asc],
          sessions_count_desc: ['sessions_count', :desc],
          users_count_asc: ['users_count', :asc],
          users_count_desc: ['users_count', :desc],
          median_time_asc: ['median_execution_time', :asc],
          median_time_desc: ['median_execution_time', :desc]
        }.freeze

        def initialize(current_user, namespace:, from:, to:, fields: nil, **optional_parameters)
          @optional_params = optional_parameters || {}
          @sort = @optional_params[:sort]

          super(current_user, namespace: namespace, from: from, to: to, fields: fields)
        end

        private

        attr_reader :sort

        def success_payload
          usage_data
        end

        def empty_payload
          []
        end

        def usage_data
          ClickHouse::Client.select(query, :main)
        end

        # Sample query output
        #
        #
        # WITH `session_stats` AS
        #   (SELECT `agent_platform_sessions`.`flow_type`,
        #           `agent_platform_sessions`.`user_id`,
        #           `agent_platform_sessions`.`session_id`,
        #           anyIfMerge(`agent_platform_sessions`.`started_event_at`) AS started_at,
        #           anyIfMerge(`agent_platform_sessions`.`finished_event_at`) AS finished_at,
        #           finished_at - started_at AS execution_time
        #    FROM `agent_platform_sessions`
        #    WHERE startsWith(namespace_path, '9970/')
        #    GROUP BY flow_type,
        #             user_id,
        #             session_id
        #    HAVING toDate(anyIfMerge(`agent_platform_sessions`.`created_event_at`)) >= '2025-11-27'
        #    AND toDate(anyIfMerge(`agent_platform_sessions`.`created_event_at`)) <= '2025-11-27'
        # SELECT `session_stats`.`flow_type`,
        #        COUNT(*) AS started_count,
        #        countIf(`session_stats`.`finished_at` IS NOT NULL) AS finished_count,
        #        median(`session_stats`.`execution_time`) AS median_execution_time_seconds,
        #        uniq(`session_stats`.`user_id`) AS users_count,
        #        divide(countIf(`session_stats`.`finished_at` IS NOT NULL), COUNT(*)) * 100 AS completion_rate_percent
        # FROM `session_stats`
        # GROUP BY flow_type
        # ORDER BY flow_type ASC

        def query
          cte_query = build_cte_query

          cte_table = Arel::Table.new(:session_stats)
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

          created_at_date = Arel::Nodes::NamedFunction.new('toDate', [
            Arel::Nodes::NamedFunction.new('anyIfMerge', [inner_table[:created_event_at]])
          ])

          started_at =
            Arel::Nodes::NamedFunction.new('anyIfMerge', [inner_table[:started_event_at]])

          finished_at =
            Arel::Nodes::NamedFunction.new('anyIfMerge', [inner_table[:finished_event_at]])

          namespace_filter =
            Arel::Nodes::NamedFunction.new('startsWith',
              [Arel.sql('namespace_path'),
                Arel::Nodes.build_quoted(namespace.traversal_path(with_organization: false))])

          date_diff =
            Arel::Nodes::NamedFunction.new('dateDiff',
              [Arel.sql('second'), Arel.sql('started_at'), Arel.sql('finished_at')])

          selects = [
            :flow_type,
            :user_id,
            :session_id,
            started_at.as('started_at'),
            finished_at.as('finished_at'),
            date_diff.as('execution_time')
          ]

          builder
            .select(*selects)
            .where(namespace_filter)
            .group(:flow_type, :user_id, :session_id)
            .having(created_at_date.gteq(from.to_date.iso8601))
            .having(created_at_date.lteq(to.to_date.iso8601))
        end

        # Builds the query that selects from CTE table
        def outer_query_for(cte_table)
          # All the fields of the query are calculated with the exception of
          # flow_type. If we are sorting by a calculated field we also need
          # to include it in the SELECT statement.
          sort_field, sort_direction = SORTING_FIELDS_MAP[sort]
          fields << sort_field.to_sym if sort_field

          available_projections = projections_for(cte_table)
          projections = available_projections.values_at(*fields).compact

          builder =
            ClickHouse::Client::QueryBuilder.new(cte_table.name)
              .select(*projections)
              .group(:flow_type)

          builder = builder.order(Arel.sql(sort_field), sort_direction) if sort_field
          builder.order(Arel.sql('flow_type'), :asc) # default order
        end

        def projections_for(cte_table)
          field_expressions = {}

          field_expressions[:flow_type] = :flow_type
          field_expressions[:users_count] =
            Arel::Nodes::NamedFunction.new('uniq', [cte_table[:user_id]]).as('users_count')

          field_expressions[:sessions_count] =
            Arel::Nodes::NamedFunction.new('uniq', [cte_table[:session_id]]).as('sessions_count')

          field_expressions[:completion_rate] =
            Arel::Nodes::NamedFunction.new(
              'round',
              [
                Arel::Nodes::Multiplication.new(
                  Arel::Nodes::NamedFunction.new('divide', [
                    Arel::Nodes::NamedFunction.new('countIf', [cte_table[:finished_at].not_eq(nil)]),
                    Arel::Nodes::NamedFunction.new('COUNT', [Arel.star])
                  ]),
                  100
                ),
                1
              ]
            ).as('completion_rate')

          field_expressions[:median_execution_time] =
            Arel::Nodes::NamedFunction.new(
              'round',
              [
                Arel::Nodes::NamedFunction.new('median', [cte_table[:execution_time]]),
                1
              ]
            ).as('median_execution_time')

          field_expressions
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
