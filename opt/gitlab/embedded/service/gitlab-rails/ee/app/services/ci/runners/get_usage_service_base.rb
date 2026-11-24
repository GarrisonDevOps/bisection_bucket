# frozen_string_literal: true

module Ci
  module Runners
    class GetUsageServiceBase
      include Gitlab::Utils::StrongMemoize

      MAX_PROJECTS_IN_GROUP = 5_000

      # Instantiates a new service
      #
      # @param [User, token String] current_user The current user for whom the report is generated
      # @param [DateTime] from_date The start date for the report data (inclusive)
      # @param [DateTime] to_date The end date for the report data (exclusive)
      # @param [Integer] max_item_count The maximum number of items to include in the report
      # @param [Project, Group, nil] scope The top-level object that owns the jobs.
      #   - Project: filter jobs from the specified project. current_user needs to be at least a maintainer
      #   - Group: filter jobs from projects under the specified group. current_user needs to be at least a maintainer
      #   - nil: use all jobs. current_user must be an admin
      # @param [Symbol, Integer] runner_type The type of CI runner to include data for
      #     Valid options are defined in `Ci::Runner.runner_types`
      # @param [Array<String>] additional_group_by_columns An array of additional columns to group the report data by.
      #
      # @return [GetUsageServiceBase]
      def initialize(
        current_user, from_date:, to_date:, max_item_count:,
        scope: nil, runner_type: nil, additional_group_by_columns: []
      )
        @current_user = current_user
        @scope = scope
        @runner_type = Ci::Runner.runner_types.fetch(runner_type) { Integer(runner_type) if runner_type }
        @from_date = from_date
        @to_date = to_date
        @max_item_count = max_item_count
        @additional_group_by_columns = additional_group_by_columns
      end

      def execute
        unless ::Gitlab::ClickHouse.configured?
          return ServiceResponse.error(message: 'ClickHouse database is not configured',
            reason: :db_not_configured)
        end

        unless Ability.allowed?(@current_user, :read_runner_usage, scope || :global)
          return ServiceResponse.error(message: 'Insufficient permissions',
            reason: :insufficient_permissions)
        end

        data = with_namespace_context do
          ::ClickHouse::Client.select(clickhouse_query, :main)
        end
        ServiceResponse.success(payload: data)
      end

      private

      attr_reader :scope, :runner_type, :from_date, :to_date, :max_item_count, :additional_group_by_columns

      # Attributes the ClickHouse query to the scope's namespace so its cost is
      # recorded per root namespace. A Project is not a Namespace, so it is
      # mapped to its project_namespace (a namespace record that is always
      # present and carries traversal_ids); passing the bare Project would be
      # silently dropped by the context type check. A nil scope is admin/global
      # and has no namespace to attribute.
      def with_namespace_context(&block)
        namespace =
          case scope
          when ::Project then scope.project_namespace
          when ::Group then scope
          end

        return yield unless namespace

        ::Gitlab::ApplicationContext.with_context(namespace: namespace, &block)
      end

      def clickhouse_query
        grouping_columns = ["#{bucket_column}_bucket", *additional_group_by_columns].join(', ')
        raw_query = <<~SQL.squish
          WITH top_buckets AS
            (
              SELECT #{bucket_column} AS #{bucket_column}_bucket
              FROM #{table_name}
              WHERE #{where_conditions}
              GROUP BY #{bucket_column}
              ORDER BY sumSimpleState(total_duration) DESC
              LIMIT {max_item_count: UInt64}
            )
          SELECT
            IF(#{table_name}.#{bucket_column} IN top_buckets, #{table_name}.#{bucket_column}, NULL)
              AS #{bucket_column}_bucket,
            #{select_list}
          FROM #{table_name}
          WHERE #{where_conditions}
          GROUP BY #{grouping_columns}
          ORDER BY #{order_list}
        SQL

        ::ClickHouse::Client::Query.new(raw_query: raw_query, placeholders: placeholders)
      end

      def table_name
        raise NotImplementedError
      end

      def bucket_column
        raise NotImplementedError
      end

      def project_ids
        case scope
        when ::Project
          [scope.id]
        when ::Group
          # rubocop: disable CodeReuse/ActiveRecord -- the number of returned IDs is limited and the logic is specific
          scope.all_projects.limit(MAX_PROJECTS_IN_GROUP).ids
          # rubocop: enable CodeReuse/ActiveRecord
        end
      end
      strong_memoize_attr :project_ids

      def select_list
        [
          *additional_group_by_columns,
          'countMerge(count_builds) AS count_builds',
          'toUInt64(sumSimpleState(total_duration) / 60000) AS total_duration_in_mins'
        ].join(', ')
      end
      strong_memoize_attr :select_list

      def order_list
        [
          "(#{bucket_column}_bucket IS NULL)",
          'total_duration_in_mins DESC',
          "#{bucket_column}_bucket ASC"
        ].join(', ')
      end
      strong_memoize_attr :order_list

      def where_conditions
        <<~SQL
          #{'runner_type = {runner_type: UInt8} AND' if runner_type}
          #{'project_id IN {project_ids: Array(UInt64)} AND' if project_ids}
          finished_at_bucket >= {from_date: DateTime('UTC', 6)} AND
          finished_at_bucket < {to_date: DateTime('UTC', 6)}
        SQL
      end
      strong_memoize_attr :where_conditions

      def placeholders
        {
          runner_type: runner_type,
          project_ids: project_ids&.to_json,
          from_date: format_date(from_date),
          to_date: format_date(to_date + 1), # Include jobs until the end of the day
          max_item_count: max_item_count
        }.compact
      end

      def format_date(date)
        date.strftime('%Y-%m-%d %H:%M:%S')
      end
    end
  end
end
