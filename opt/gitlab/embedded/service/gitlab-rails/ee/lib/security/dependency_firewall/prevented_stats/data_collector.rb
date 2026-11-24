# frozen_string_literal: true

module Security
  module DependencyFirewall
    module PreventedStats
      # Where ClickHouse reads apply, both projects and groups read the Siphon replica. Otherwise projects
      # read PostgreSQL at query time and groups read the periodically refreshed summary table.
      class DataCollector
        # Rule types behind the vulnerabilities card.
        VULNERABILITY_RULE_TYPES = ::Security::DependencyFirewallPolicyRule.severity_carrying_types

        def initialize(container:, from:)
          @container = container
          @from = from
        end

        def counts
          case container
          when Project
            clickhouse_counts || PostgresqlCollector.new(container: container, from: from).counts
          when Group
            return unless Availability.group_prevented_stats_enabled?(container)

            clickhouse_counts || group_counts
          end
        end

        private

        attr_reader :container, :from

        # One failing field fails the whole GraphQL request, so a ClickHouse error falls back to the PostgreSQL paths.
        def clickhouse_counts
          return unless clickhouse_reads?

          ClickHouseCollector.new(container: container, from: from).counts
        rescue ::ClickHouse::Client::Error, *::Gitlab::HTTP::HTTP_ERRORS => e
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
            e, container_type: container.class.name, container_id: container.id
          )
          nil
        end

        # Without Siphon replicating the ledger the replica is empty, so ClickHouse would report zeros
        # rather than fail. The replication check queries ClickHouse, so it runs last.
        def clickhouse_reads?
          ::Gitlab::ClickHouse.enabled_for_analytics?(container) &&
            Feature.enabled?(:dependency_firewall_clickhouse_reads, container.root_ancestor) &&
            ::Gitlab::ClickHouse.siphon_enabled?(::Security::DependencyFirewallPreventedPackage.table_name)
        end

        # Only the stored 7 and 30 day windows are served. A row up to one day stale is accepted so a
        # request after midnight, before the next refresh, still gets the latest row; a miss schedules a refresh.
        def group_counts
          window_days = (utc_today - from.to_date).to_i + 1
          return unless Security::DependencyFirewallNamespacePreventedStat::WINDOWS.include?(window_days)

          stat = Security::DependencyFirewallNamespacePreventedStat.find_for_namespace_window(container.id, window_days)
          return stat.to_counts if stat && stat.window_start >= utc_today - window_days

          schedule_refresh
          nil
        end

        # Best effort in production: a failure to enqueue must not fail the dashboard read.
        def schedule_refresh
          RefreshGroupPreventedStatsWorker.schedule([container.id])
        rescue StandardError => e
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e, group_id: container.id)
        end

        def utc_today
          Time.current.utc.to_date
        end
      end
    end
  end
end
