# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class RunModeEnum < BaseEnum
        graphql_name 'SecurityScanProfileRunMode'
        description 'Whether a triage and remediation capability runs automatically or on demand.'

        value 'MANUAL', value: 'manual', description: 'Run only when triggered by a user.',
          experiment: { milestone: '19.4' }
        value 'AUTO', value: 'auto', description: 'Run automatically as findings appear.',
          experiment: { milestone: '19.4' }
      end
    end
  end
end
