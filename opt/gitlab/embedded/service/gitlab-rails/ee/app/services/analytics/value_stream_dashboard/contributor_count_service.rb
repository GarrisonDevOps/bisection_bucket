# frozen_string_literal: true

module Analytics
  module ValueStreamDashboard
    class ContributorCountService
      include Gitlab::Allowable

      def initialize(namespace:, current_user:, from:, to:)
        @namespace = namespace
        @current_user = current_user
        @from = from
        @to = to
      end

      def execute
        return feature_unavailable_error unless Gitlab::ClickHouse.enabled_for_contributions?(namespace)
        return not_authorized_error unless authorized?

        ServiceResponse.success(payload: { count: contributor_count })
      end

      private

      attr_reader :namespace, :current_user, :from, :to

      def contributions_query
        <<~SQL
          SELECT count(distinct "contributions"."author_id") AS contributor_count
          FROM (
            SELECT
              argMax(author_id, "contributions_new".version) AS author_id,
              argMax(deleted, "contributions_new".version) AS deleted
            FROM "contributions_new"
              WHERE startsWith("contributions_new"."path", {namespace_path:String})
              AND "contributions_new"."created_at" >= {from:Date}
              AND "contributions_new"."created_at" < {to:Date} + 1
            GROUP BY id
          ) contributions
          WHERE deleted = false
        SQL
      end

      def authorized?
        case namespace
        when Namespaces::ProjectNamespace
          can?(current_user, :read_project_level_value_stream_dashboard_overview_counts, namespace.project)
        when Group
          can?(current_user, :read_group_analytics_dashboards, namespace)
        else
          false
        end
      end

      def feature_unavailable_error
        ServiceResponse.error(
          message: s_('VsdContributorCount|the ClickHouse data store is not available for this namespace')
        )
      end

      def not_authorized_error
        ServiceResponse.error(message: s_('404|Not found'))
      end

      def contributor_count
        query = ClickHouse::Client::Query.new(raw_query: contributions_query, placeholders: placeholders)
        ClickHouse::Client.select(query, :main).first['contributor_count']
      end

      def namespace_path
        namespace.traversal_path(with_organization: true)
      end

      def format_date(date)
        date.to_date.iso8601
      end

      def placeholders
        {
          namespace_path: namespace_path,
          from: format_date(from),
          to: format_date(to)
        }
      end
    end
  end
end
