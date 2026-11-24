# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes, GraphQL/ExtractType -- not applicable

    class SecurityMetricsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'SecurityMetrics'
      description 'Represents security metrics'

      # Resolves to the project, group or organization itself. The metrics are vulnerability data, so they
      # need read_vulnerability, which has a project boundary only: Group.securityMetrics and
      # Organization.securityMetrics stay unavailable to fine-grained tokens.
      authorize_granular_token permissions: :read_vulnerability, boundary: :itself, boundary_type: :project

      field :vulnerabilities_per_severity,
        ::Types::Security::VulnerabilitiesPerSeverityType,
        null: true,
        description: 'Count of open vulnerabilities per severity level.
This feature is currently under development and not yet available for general use',
        resolver: ::Resolvers::Security::VulnerabilitiesPerSeverityResolver

      field :vulnerabilities_over_time,
        ::Types::Security::VulnerabilitiesOverTimeType.connection_type,
        null: true,
        description: 'Vulnerability metrics over time with filtering and grouping capabilities.
This feature is currently under development and not yet available for general use',
        resolver: ::Resolvers::Security::VulnerabilitiesOverTimeResolver

      field :risk_score,
        ::Types::Security::RiskScoreType,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Total risk score information. By default, excludes vulnerabilities ' \
          "that are no longer detected on the default branch.\n" \
          'This feature is currently under development and not yet available for general use.',
        resolver: ::Resolvers::Security::RiskScoreResolver

      field :vulnerabilities_by_age,
        [::Types::Security::VulnerabilitiesByAgeType],
        null: true,
        description: 'Vulnerability age statistics based on predefined age bands.
See [`VulnerabilitiesByAge`](#vulnerabilitiesbyage) for details.
This feature is currently under development and not yet available for general use',
        experiment: { milestone: '18.9' },
        resolver: ::Resolvers::Security::VulnerabilitiesByAgeResolver

      field :vulnerabilities_by_identifier,
        [::Types::Security::VulnerabilitiesByIdentifierType],
        null: true,
        description: 'Vulnerability identifier statistics with filtering.
This feature is currently under development and not yet available for general use',
        experiment: { milestone: '18.10' },
        resolver: ::Resolvers::Security::VulnerabilitiesByIdentifierResolver

      field :vulnerability_resolution_funnel,
        ::Types::Security::VulnerabilityResolutionFunnelType,
        null: true,
        experiment: { milestone: '19.2' },
        description: 'Adoption funnel for AI-assisted vulnerability resolution. Returns `null` for organizations.
This feature is currently under development and not yet available for general use.',
        resolver: ::Resolvers::Security::VulnerabilityResolutionFunnelResolver

      field :mttr_over_time,
        [::Types::Security::MttrOverTimeBucketType],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Weekly mean time to remediation (MTTR) of vulnerabilities. ' \
          "#{::Resolvers::Security::MttrOverTimeResolver::DETECTION_WINDOW_NOTE} " \
          'Returns `null` unless the `security_dashboard_mttr_chart` feature flag is enabled.
This feature is currently under development and not yet available for general use.',
        resolver: ::Resolvers::Security::MttrOverTimeResolver
    end

    # rubocop: enable Graphql/AuthorizeTypes, GraphQL/ExtractType
  end
end
