# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class AdvancedSastPartialScanEnum < BaseEnum
        graphql_name 'SecurityScanProfileAdvancedSastPartialScan'
        description 'Controls GitLab Advanced SAST diff-based scanning.'

        value 'DIFFERENTIAL', value: 'differential', description: 'Enable diff-based scanning.',
          experiment: { milestone: '19.4' }
        value 'DISABLED', value: 'false', description: 'Disable diff-based scanning.',
          experiment: { milestone: '19.4' }
      end
    end
  end
end
