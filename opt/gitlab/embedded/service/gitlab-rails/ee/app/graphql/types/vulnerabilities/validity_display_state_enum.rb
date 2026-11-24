# frozen_string_literal: true

module Types
  module Vulnerabilities
    class ValidityDisplayStateEnum < BaseEnum
      graphql_name 'VulnerabilityValidityDisplayState'
      description 'Validity state of a secret finding, derived from the token status ' \
        'and the current vendor support for the detecting analyzer.'

      value 'ACTIVE', value: 'active', description: 'Token was verified and is active.'
      value 'INACTIVE', value: 'inactive', description: 'Token was verified and is inactive.'
      value 'UNKNOWN', value: 'unknown', description: 'Token was checked but the vendor gave no verdict.'
      value 'PENDING_VERIFICATION', value: 'pending_verification',
        description: 'Token type is supported but no check has completed yet.'
      value 'NOT_CHECKED_BY_ANALYZER', value: 'not_checked_by_analyzer',
        description: 'Token type is only verified for findings from a different analyzer.'
      value 'NO_VENDOR_SUPPORT', value: 'no_vendor_support',
        description: 'No verifier exists for the token type.'
    end
  end
end
