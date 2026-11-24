# frozen_string_literal: true

module Types
  module Vulnerabilities
    class SensitiveDataFilterEnum < BaseEnum
      graphql_name 'VulnerabilitySensitiveDataFilter'
      description 'Whether the component a vulnerability is in handles sensitive data, used to filter vulnerabilities'

      value 'SENSITIVE', value: 'true', description: 'Component handles sensitive data.'
      value 'NOT_SENSITIVE', value: 'false', description: 'Component does not handle sensitive data.'
      value 'UNKNOWN', value: 'unknown', description: 'Sensitive data handling is unknown.'
    end
  end
end
