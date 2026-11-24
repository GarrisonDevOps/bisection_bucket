# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class SecretDetectionFalsePositiveInputType < BaseInputObject
        graphql_name 'SecurityScanProfileSecretDetectionFalsePositiveInput'
        description 'Configuration for the secret detection false positive detection trigger of a ' \
          'triage and remediation scan profile.'

        argument :severity_level, ::Types::VulnerabilitySeverityEnum,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Minimum vulnerability severity that triggers false positive detection. ' \
            'Findings below this threshold are skipped.'

        argument :run_mode, ::Types::Security::ScanProfiles::RunModeEnum,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Whether false positive detection runs automatically or only when triggered by a user.'
      end
    end
  end
end
