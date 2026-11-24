# frozen_string_literal: true

module Security
  module DependencyFirewall
    module PreventedStats
      class PostgresqlCollector
        def initialize(container:, from:)
          @container = container
          @from = from
        end

        def counts
          {
            vulnerabilities: {
              prevented: distinct_blocked(DataCollector::VULNERABILITY_RULE_TYPES),
              by_severity: blocked_by_max_severity
            },
            malicious: rule_type_counts(:malicious),
            license: rule_type_counts(:license)
          }
        end

        private

        attr_reader :container, :from

        def rule_type_counts(rule_type)
          {
            prevented: distinct_blocked(rule_type),
            warned_only: model.distinct_warned_only_count(
              projects: project_scope, rule_types: rule_type, from: from
            )
          }
        end

        def distinct_blocked(rule_types)
          model.distinct_blocked_count(projects: project_scope, rule_types: rule_types, from: from)
        end

        # Each purl counts once at its max severity, so the breakdown sums to the card total.
        def blocked_by_max_severity
          grouped = model.blocked_count_by_max_severity(
            projects: project_scope, rule_types: DataCollector::VULNERABILITY_RULE_TYPES, from: from
          )

          grouped.each_with_object({}) do |(severity_int, count), result|
            severity = model.severities.key(severity_int) || 'unknown'
            result[severity] = result.fetch(severity, 0) + count
          end
        end

        def project_scope
          [container.id]
        end

        def model
          ::Security::DependencyFirewallPreventedPackage
        end
      end
    end
  end
end
