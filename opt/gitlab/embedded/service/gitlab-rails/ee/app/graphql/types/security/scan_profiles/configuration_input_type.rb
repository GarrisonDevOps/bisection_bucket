# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class ConfigurationInputType < BaseInputObject
        graphql_name 'SecurityScanProfileConfigurationInput'
        description 'Typed configuration for a scan profile trigger. Exactly one member may be set, ' \
          'and it must match the scan profile type.'

        one_of

        argument :dependency_scanning,
          ::Types::Security::ScanProfiles::DependencyScanningConfigurationInputType,
          required: false,
          experiment: { milestone: '19.5' },
          description: 'Configuration for a dependency scanning scan profile.'

        argument :dependency_scanning_post_processing,
          ::Types::Security::ScanProfiles::DependencyScanningPostProcessingConfigurationInputType,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Configuration for a dependency scanning post-processing scan profile.'

        argument :secret_detection,
          ::Types::Security::ScanProfiles::SecretDetectionConfigurationInputType,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Configuration for a secret detection scan profile.'

        argument :sast,
          ::Types::Security::ScanProfiles::SastConfigurationInputType,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Configuration for a SAST scan profile.'

        argument :triage_and_remediation,
          ::Types::Security::ScanProfiles::TriageAndRemediationConfigurationInputType,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Configuration for a triage and remediation scan profile.'
      end
    end
  end
end
