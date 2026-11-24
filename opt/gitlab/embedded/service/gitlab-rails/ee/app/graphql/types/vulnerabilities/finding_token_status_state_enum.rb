# frozen_string_literal: true

module Types
  module Vulnerabilities
    class FindingTokenStatusStateEnum < BaseEnum
      graphql_name 'VulnerabilityFindingTokenStatusState'
      description 'Status of a secret token found in a vulnerability'

      value 'UNKNOWN', value: 'unknown', description: 'Token status is unknown.'
      value 'ACTIVE', value: 'active', description: 'Token is active and can be exploited.'
      value 'INACTIVE', value: 'inactive', description: 'Token is inactive and cannot be exploited.'
    end
  end
end
