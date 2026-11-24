# frozen_string_literal: true

module Gitlab
  module ContributionAnalytics
    class ClickHouseDataCollector
      attr_reader :group, :from, :to

      def initialize(group:, from:, to:)
        @group = group
        @from = from.utc.beginning_of_day.to_f
        @to = to.utc.end_of_day.to_f
      end

      # GraphQL requests carry no namespace in the application context, because it
      # is pushed from controller instance variables the GraphQL endpoint never
      # sets. Publish it here so the query is attributable in system.query_log.
      def totals_by_author_target_type_action
        ::Gitlab::ApplicationContext.with_context(namespace: group) do
          query = ::ClickHouse::Client::Query.new(raw_query: clickhouse_query, placeholders: placeholders)
          ::ClickHouse::Client.select(query, :main).each_with_object({}) do |row, hash|
            hash[[row['author_id'], row['target_type'].presence, row['action']]] = row['count']
          end
        end
      end

      private

      def group_path
        # trailing slash required to denote end of path because we use startsWith
        # to get self and descendants
        group.traversal_path(with_organization: true)
      end

      def clickhouse_query
        <<~CH
          SELECT count(*) AS count,
            "contributions_new"."author_id" AS author_id,
            "contributions_new"."target_type" AS target_type,
            "contributions_new"."action" AS action
          FROM (
            SELECT
              id,
              argMax(deleted, contributions_new.version) AS deleted,
              argMax(author_id, contributions_new.version) AS author_id,
              CASE
                WHEN argMax(target_type, contributions_new.version) IN ('Issue', 'WorkItem') THEN 'Issue'
                ELSE argMax(target_type, contributions_new.version)
              END AS target_type,
              argMax(action, contributions_new.version) AS action
            FROM contributions_new
              WHERE startsWith(path, {group_path:String})
              AND "contributions_new"."created_at" >= {from:DateTime64(6, 'UTC')}
              AND "contributions_new"."created_at" <= {to:DateTime64(6, 'UTC')}
              AND (
                (
                  "contributions_new"."action" = 5 AND "contributions_new"."target_type" = ''
                )
                OR
                (
                  "contributions_new"."action" IN (1, 3, 7, 12)
                  AND "contributions_new"."target_type" IN ('MergeRequest', 'Issue', 'WorkItem')
                )
              )
            GROUP BY id
          ) contributions_new
          WHERE deleted = false
          GROUP BY "contributions_new"."action","contributions_new"."target_type","contributions_new"."author_id"
        CH
      end

      def placeholders
        {
          group_path: group_path,
          from: from,
          to: to
        }
      end
    end
  end
end
