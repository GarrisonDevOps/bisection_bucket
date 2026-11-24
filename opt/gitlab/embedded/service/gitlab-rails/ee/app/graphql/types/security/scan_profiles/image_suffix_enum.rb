# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class ImageSuffixEnum < BaseEnum
        graphql_name 'SecurityScanProfileImageSuffix'
        description 'Suffix appended to the analyzer image name.'

        value 'DEFAULT', value: '', description: 'No suffix; use the standard analyzer image.',
          experiment: { milestone: '19.3' }
        value 'FIPS', value: '-fips', description: 'Use the FIPS-compliant analyzer image.',
          experiment: { milestone: '19.3' }
      end
    end
  end
end
