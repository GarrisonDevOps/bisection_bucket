# frozen_string_literal: true

module Types
  module Vulnerabilities
    class SecurityBoundaryFilterEnum < BaseEnum
      graphql_name 'VulnerabilitySecurityBoundaryFilter'
      description 'Security boundary of the component a vulnerability is in, used to filter vulnerabilities'

      value 'NETWORK_ACCESS', value: 'NETWORK_ACCESS', description: 'Network Access.'
      value 'USER_INPUT', value: 'USER_INPUT', description: 'User Input.'
      value 'PARTNER_BOUNDARY', value: 'PARTNER_BOUNDARY', description: 'Partner Boundary.'
      value 'TRUSTED_SERVICE', value: 'TRUSTED_SERVICE', description: 'Trusted Service.'
      value 'INTERNAL_ONLY', value: 'INTERNAL_ONLY', description: 'Internal Only.'
      value 'ISOLATED', value: 'ISOLATED', description: 'Isolated.'
      value 'UNKNOWN', value: 'unknown', description: 'Security boundary is unknown.'
    end
  end
end
