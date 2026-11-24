# frozen_string_literal: true

module Types
  module Security
    module Ascp
      class SecurityBoundaryEnum < BaseEnum
        graphql_name 'AscpSecurityBoundary'
        description 'Security boundaries an ASCP component sits on'

        value 'NETWORK_ACCESS',    description: 'Network Access.'
        value 'USER_INPUT',        description: 'User Input.'
        value 'PARTNER_BOUNDARY',  description: 'Partner Boundary.'
        value 'TRUSTED_SERVICE',   description: 'Trusted Service.'
        value 'INTERNAL_ONLY',     description: 'Internal Only.'
        value 'ISOLATED',          description: 'Isolated.'
      end
    end
  end
end
