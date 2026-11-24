# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class SastFalsePositiveInputType < BaseInputObject
        graphql_name 'SecurityScanProfileSastFalsePositiveInput'
        description 'Configuration for the SAST false positive detection trigger of a ' \
          'triage and remediation scan profile.'

        argument :severity_level, ::Types::VulnerabilitySeverityEnum,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Minimum vulnerability severity that triggers false positive detection. ' \
            'Findings below this threshold are skipped.'

        argument :cwe_classes, [::Types::Security::CweIdentifierType],
          required: false,
          validates: { length: { maximum: 50 } },
          experiment: { milestone: '19.4' },
          description: 'CWE identifiers to restrict false positive detection to.'

        argument :run_mode, ::Types::Security::ScanProfiles::RunModeEnum,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Whether false positive detection runs automatically or only when triggered by a user.'
      end
    end
  end
end
