# frozen_string_literal: true

module Types
  module Vulnerabilities
    class AuthorizationFilterEnum < BaseEnum
      graphql_name 'VulnerabilityAuthorizationFilter'
      description 'Authorization required by the component a vulnerability is in, used to filter vulnerabilities'

      value 'ELEVATED', value: 'elevated', description: 'Component requires elevated privileges.'
      value 'STANDARD', value: 'standard', description: 'Component requires standard privileges.'
      value 'UNKNOWN', value: 'unknown', description: 'Authorization is unknown.'
    end
  end
end
