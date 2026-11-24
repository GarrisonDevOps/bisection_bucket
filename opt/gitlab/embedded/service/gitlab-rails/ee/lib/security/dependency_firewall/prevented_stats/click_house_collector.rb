# frozen_string_literal: true

module Security
  module DependencyFirewall
    module PreventedStats
      # Reads the Siphon replica (ReplacingMergeTree). Every query dedupes with argMax on
      # _siphon_replicated_at and drops deleted versions instead of relying on background merges.
      # Must return the same numbers as PostgresqlCollector.
      class ClickHouseCollector
        TABLE = 'siphon_dependency_firewall_prevented_packages'

        def initialize(container:, from:)
          @container = container
          @from = from.utc.to_f
        end

        def counts
          ::Gitlab::ApplicationContext.with_context(**namespace_context) do
            totals = select(totals_query).first || {}

            {
              vulnerabilities: {
                prevented: totals.fetch('vulnerabilities_prevented', 0),
                by_severity: severity_breakdown
              },
              malicious: {
                prevented: totals.fetch('malicious_prevented', 0),
                warned_only: totals.fetch('malicious_warned_only', 0)
              },
              license: {
                prevented: totals.fetch('license_prevented', 0),
                warned_only: totals.fetch('license_warned_only', 0)
              }
            }
          end
        end

        private

        attr_reader :container, :from

        def select(raw_query)
          query = ::ClickHouse::Client::Query.new(raw_query: raw_query, placeholders: placeholders)
          ::ClickHouse::Client.select(query, :main)
        end

        def totals_query
          <<~CH
            SELECT
              countDistinctIf(identifier, rule_type IN (#{vulnerability_rule_types}) AND #{blocked_in_window}) AS vulnerabilities_prevented,
              countDistinctIf(identifier, rule_type = #{rule_type(:malicious)} AND #{blocked_in_window}) AS malicious_prevented,
              countDistinctIf(identifier, rule_type = #{rule_type(:malicious)} AND #{warned_only_in_window}) AS malicious_warned_only,
              countDistinctIf(identifier, rule_type = #{rule_type(:license)} AND #{blocked_in_window}) AS license_prevented,
              countDistinctIf(identifier, rule_type = #{rule_type(:license)} AND #{warned_only_in_window}) AS license_warned_only
            FROM (#{deduped_rows}) AS rows
            WHERE deleted = false
          CH
        end

        # Each distinct purl counts once, at its max severity across vulnerability-family rows,
        # so the breakdown sums to the card total (mirrors PostgresqlCollector).
        def severity_breakdown_query
          <<~CH
            SELECT max_severity, count(*) AS count
            FROM (
              SELECT identifier, max(severity) AS max_severity
              FROM (#{deduped_rows}) AS rows
              WHERE deleted = false
                AND rule_type IN (#{vulnerability_rule_types})
                AND #{blocked_in_window}
              GROUP BY identifier
            ) AS per_identifier
            GROUP BY max_severity
          CH
        end

        def severity_breakdown
          select(severity_breakdown_query).each_with_object({}) do |row, result|
            severity = severity_names.fetch(row['max_severity'], 'unknown')
            result[severity] = result.fetch(severity, 0) + row['count']
          end
        end

        def deduped_rows
          <<~CH
            SELECT
              id,
              argMax(identifier, _siphon_replicated_at) AS identifier,
              argMax(rule_type, _siphon_replicated_at) AS rule_type,
              argMax(severity, _siphon_replicated_at) AS severity,
              argMax(last_blocked_at, _siphon_replicated_at) AS last_blocked_at,
              argMax(last_warned_at, _siphon_replicated_at) AS last_warned_at,
              argMax(_siphon_deleted, _siphon_replicated_at) AS deleted
            FROM #{TABLE}
            WHERE #{scope_condition}
            GROUP BY id
          CH
        end

        def blocked_in_window
          "last_blocked_at >= {from:DateTime64(6, 'UTC')}"
        end

        def warned_only_in_window
          "last_warned_at >= {from:DateTime64(6, 'UTC')} AND " \
            "(last_blocked_at IS NULL OR last_blocked_at < {from:DateTime64(6, 'UTC')})"
        end

        def scope_condition
          if container.is_a?(Project)
            'traversal_path = {traversal_path:String}'
          else
            # trailing slash in traversal_path denotes end of path segment for startsWith
            'startsWith(traversal_path, {traversal_path:String})'
          end
        end

        def placeholders
          namespace = container.is_a?(Project) ? container.project_namespace : container

          { from: from, traversal_path: namespace.traversal_path(with_organization: true) }
        end

        # Internal enum constants, not user input; inlined because placeholders cover values,
        # and these are compile-time integers from the Rails enum.
        def rule_type(name)
          ::Security::DependencyFirewallPolicyRule.types.fetch(name.to_s)
        end

        def vulnerability_rule_types
          DataCollector::VULNERABILITY_RULE_TYPES.map { |name| rule_type(name) }.join(', ')
        end

        def severity_names
          ::Security::DependencyFirewallPreventedPackage.severities.invert
        end

        def namespace_context
          { namespace: container.is_a?(Project) ? container.namespace : container }
        end
      end
    end
  end
end
