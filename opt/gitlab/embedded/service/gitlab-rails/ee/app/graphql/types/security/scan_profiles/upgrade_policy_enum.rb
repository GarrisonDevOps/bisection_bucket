# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class UpgradePolicyEnum < BaseEnum
        graphql_name 'SecurityScanProfileUpgradePolicy'
        description 'Highest version bump allowed when remediating a dependency.'

        value 'PATCH', value: 'patch', description: 'Allow patch upgrades only.',
          experiment: { milestone: '19.3' }
        value 'MINOR', value: 'minor', description: 'Allow patch and minor upgrades.',
          experiment: { milestone: '19.3' }
        value 'MAJOR', value: 'major', description: 'Allow any upgrade.',
          experiment: { milestone: '19.3' }
      end
    end
  end
end
