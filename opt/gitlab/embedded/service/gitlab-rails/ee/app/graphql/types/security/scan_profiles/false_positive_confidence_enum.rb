# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class FalsePositiveConfidenceEnum < BaseEnum
        graphql_name 'SecurityScanProfileFalsePositiveConfidence'
        description 'False positive assessment a finding must carry to be acted on.'

        value 'LIKELY_FALSE_POSITIVE', value: 'likely_false_positive',
          description: 'Restrict to findings assessed as likely false positives.',
          experiment: { milestone: '19.4' }
        value 'LIKELY_NOT_FALSE_POSITIVE', value: 'likely_not_false_positive',
          description: 'Restrict to findings assessed as likely not false positives.',
          experiment: { milestone: '19.4' }
      end
    end
  end
end
