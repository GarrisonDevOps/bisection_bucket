# frozen_string_literal: true

module Types
  module Vulnerabilities
    class AuthenticationFilterEnum < BaseEnum
      graphql_name 'VulnerabilityAuthenticationFilter'
      description 'Whether the component a vulnerability is in requires authentication, used to filter vulnerabilities'

      value 'REQUIRED', value: 'true', description: 'Component requires authentication.'
      value 'NOT_REQUIRED', value: 'false', description: 'Component does not require authentication.'
      value 'UNKNOWN', value: 'unknown', description: 'Authentication requirement is unknown.'
    end
  end
end
