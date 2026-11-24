# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class TriageAndRemediationConfigurationInputType < BaseInputObject
        graphql_name 'SecurityScanProfileTriageAndRemediationConfigurationInput'
        description 'Configuration for a triage and remediation scan profile trigger. Exactly one member may ' \
          'be set, and it must match the trigger type it is attached to.'

        one_of

        argument :sbom_ingested,
          ::Types::Security::ScanProfiles::DependencyScanningPostProcessingConfigurationInputType,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Configuration for the SBOM ingested trigger.'

        argument :sast_false_positive,
          ::Types::Security::ScanProfiles::SastFalsePositiveInputType,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Configuration for the SAST false positive detection trigger.'

        argument :sast_vulnerability_resolution,
          ::Types::Security::ScanProfiles::SastVulnerabilityResolutionInputType,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Configuration for the SAST vulnerability resolution trigger.'

        argument :secret_detection_false_positive,
          ::Types::Security::ScanProfiles::SecretDetectionFalsePositiveInputType,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Configuration for the secret detection false positive detection trigger.'

        argument :vulnerability_enrichment,
          ::Types::Security::ScanProfiles::VulnerabilityEnrichmentInputType,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Configuration for the vulnerability enrichment trigger.'
      end
    end
  end
end
