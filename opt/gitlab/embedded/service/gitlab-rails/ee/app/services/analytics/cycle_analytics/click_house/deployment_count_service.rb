# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    module ClickHouse
      class DeploymentCountService
        DEPLOYMENT_COUNT_QUERY = <<~SQL
          WITH deployments AS (
            SELECT
              id,
              argMax(status, _siphon_replicated_at) AS status,
              argMax(environment_id, _siphon_replicated_at) AS environment_id,
              argMax(_siphon_deleted, _siphon_replicated_at) AS is_deleted
            FROM siphon_deployments
            WHERE startsWith(traversal_path, {traversal_path:String})
              AND finished_at >= {from_date:DateTime('UTC', 6)}
              AND finished_at <= {to_date:DateTime('UTC', 6)}
            GROUP BY id
            HAVING is_deleted = false
          ),
          environments AS (
            SELECT
              id,
              argMax(tier, _siphon_replicated_at) AS tier,
              argMax(_siphon_deleted, _siphon_replicated_at) AS is_deleted
            FROM siphon_environments
            WHERE startsWith(traversal_path, {traversal_path:String})
            GROUP BY id
            HAVING is_deleted = false
          )
          SELECT count(*) AS deployment_count
          FROM deployments
          INNER JOIN environments ON environments.id = deployments.environment_id
          WHERE deployments.status = {success_status:Int8}
            AND environments.tier = {production_tier:Int8}
        SQL

        def initialize(traversal_path:, from:, to:)
          @traversal_path = traversal_path
          @from = from
          @to = to
        end

        def execute
          query = ::ClickHouse::Client::Query.new(
            raw_query: DEPLOYMENT_COUNT_QUERY,
            placeholders: placeholders
          )

          ::ClickHouse::Client.select(query, :main).first['deployment_count'].to_i
        end

        private

        attr_reader :traversal_path, :from, :to

        def placeholders
          {
            traversal_path: traversal_path,
            success_status: ::Deployment.statuses[:success],
            production_tier: ::Environment.tiers[:production],
            from_date: from.beginning_of_day.utc.strftime('%Y-%m-%d %H:%M:%S'),
            to_date: to.end_of_day.utc.strftime('%Y-%m-%d %H:%M:%S')
          }
        end
      end
    end
  end
end
