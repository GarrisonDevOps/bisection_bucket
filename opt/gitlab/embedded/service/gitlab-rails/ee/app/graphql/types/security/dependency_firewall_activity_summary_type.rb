# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- authorization is handled on the parent field
    class DependencyFirewallActivitySummaryType < BaseObject
      graphql_name 'DependencyFirewallActivitySummary'
      description 'Aggregate dependency firewall enforcement activity totals for a group or project.'
      authorize_granular_token parent_authorizes: :read_security_policy

      # The ledger keeps only the latest timestamps, so these counts can't stop at `to`.
      PREVENTED_NOTE = 'Counts from `from` up to now; `to` does not apply. ' \
        'For groups, values come from a periodically refreshed summary and are returned only when the ' \
        '`dependency_firewall_group_prevented_stats` feature flag is enabled and `from` is 6 or 29 days ' \
        'before the current UTC date. Null when not available.'

      field :active_rules, GraphQL::Types::Int, null: false,
        description: 'Number of active (enabled) dependency firewall rules.'
      field :allowed, GraphQL::Types::Int, null: false,
        description: 'Total allowed (pass-through) enforcement events in the window.'
      field :blocked, GraphQL::Types::Int, null: false,
        description: 'Total blocked enforcement events in the window.'
      field :blocking_rules, GraphQL::Types::Int, null: false,
        description: 'Number of active rules in enforce (blocking) mode.'
      field :total_triggers, GraphQL::Types::Int, null: false,
        description: 'Total enforcement events (blocked + warned + allowed) in the window.'
      field :warned, GraphQL::Types::Int, null: false,
        description: 'Total warned enforcement events in the window.'
      field :warning_rules, GraphQL::Types::Int, null: false,
        description: 'Number of active rules in warn mode.'

      # rubocop: disable GraphQL/ExtractType -- the summary type is intentionally flat, matching its existing fields
      field :license_risks_prevented, GraphQL::Types::Int, null: true,
        experiment: { milestone: '19.5' },
        description: "Number of distinct package versions blocked by license rules. #{PREVENTED_NOTE}"
      field :license_risks_warned_only, GraphQL::Types::Int, null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of distinct package versions warned but never blocked by license rules. ' \
          "#{PREVENTED_NOTE}"
      field :malicious_packages_prevented, GraphQL::Types::Int, null: true,
        experiment: { milestone: '19.5' },
        description: "Number of distinct package versions blocked by malicious-package rules. #{PREVENTED_NOTE}"
      field :malicious_packages_warned_only, GraphQL::Types::Int, null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of distinct package versions warned but never blocked by malicious-package rules. ' \
          "#{PREVENTED_NOTE}"
      field :vulnerabilities_prevented, GraphQL::Types::Int, null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of distinct package versions blocked by risk-severity rules. ' \
          "#{PREVENTED_NOTE}"
      field :vulnerabilities_prevented_by_severity, [Types::Security::DependencyFirewallSeverityCountType],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Breakdown of prevented packages by their highest carried severity. Sums to the prevented ' \
          "total. #{PREVENTED_NOTE}"
      # rubocop: enable GraphQL/ExtractType

      def vulnerabilities_prevented_by_severity
        object.vulnerabilities_prevented_by_severity
          &.sort_by { |severity, _count| -::Enums::Vulnerability.severity_levels.fetch(severity, 0) }
          &.map { |severity, count| { severity: severity, count: count } }
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
