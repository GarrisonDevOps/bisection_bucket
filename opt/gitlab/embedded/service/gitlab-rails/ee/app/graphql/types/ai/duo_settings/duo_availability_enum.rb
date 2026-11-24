# frozen_string_literal: true

module Types
  module Ai
    module DuoSettings
      class DuoAvailabilityEnum < BaseEnum
        graphql_name 'DuoAvailability'
        description 'GitLab Duo availability states for an admin-locked namespace override.'

        value 'ALWAYS_ON', value: 'always_on',
          description: 'Duo is on and group Owners cannot turn it off.'
        value 'DEFAULT_ON', value: 'default_on',
          description: 'Duo is on by default but group Owners can turn it off.'
        value 'DEFAULT_OFF', value: 'default_off',
          description: 'Duo is off by default but group Owners can turn it on.'
        value 'NEVER_ON', value: 'never_on',
          description: 'Duo is off and group Owners cannot turn it on.'
      end
    end
  end
end
