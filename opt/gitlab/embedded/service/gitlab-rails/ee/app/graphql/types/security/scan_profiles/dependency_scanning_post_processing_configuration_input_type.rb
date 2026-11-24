# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class DependencyScanningPostProcessingConfigurationInputType < BaseInputObject
        graphql_name 'SecurityScanProfileDependencyScanningPostProcessingConfigurationInput'
        description 'Configuration for a dependency scanning post-processing scan profile.'

        argument :auto_remediation, ::Types::Security::ScanProfiles::AutoRemediationInputType,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Auto-remediation configuration.'
      end
    end
  end
end
