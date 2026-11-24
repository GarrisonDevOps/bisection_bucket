# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class SecretDetectionFalsePositiveConfigurationType < BaseObject
        graphql_name 'SecretDetectionFalsePositiveConfiguration'
        description 'Configuration for the secret detection false positive detection trigger of a ' \
          'triage and remediation scan profile.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :severity_level, ::Types::VulnerabilitySeverityEnum,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Minimum vulnerability severity that triggers false positive detection.'

        field :run_mode, ::Types::Security::ScanProfiles::RunModeEnum,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Whether false positive detection runs automatically or on demand.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
