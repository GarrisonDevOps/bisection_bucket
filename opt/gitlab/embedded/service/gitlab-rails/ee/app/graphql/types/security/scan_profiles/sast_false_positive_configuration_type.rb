# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class SastFalsePositiveConfigurationType < BaseObject
        graphql_name 'SastFalsePositiveConfiguration'
        description 'Configuration for the SAST false positive detection trigger of a ' \
          'triage and remediation scan profile.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :severity_level, ::Types::VulnerabilitySeverityEnum,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Minimum vulnerability severity that triggers false positive detection.'

        field :cwe_classes, [GraphQL::Types::String],
          null: true,
          experiment: { milestone: '19.4' },
          description: 'CWE identifiers false positive detection is restricted to.'

        field :run_mode, ::Types::Security::ScanProfiles::RunModeEnum,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Whether false positive detection runs automatically or on demand.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
