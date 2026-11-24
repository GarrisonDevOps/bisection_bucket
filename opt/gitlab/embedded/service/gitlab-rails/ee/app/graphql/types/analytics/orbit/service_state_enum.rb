# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class ServiceStateEnum < BaseEnum
        graphql_name 'OrbitServiceState'
        description 'Health state of the Orbit service or of one of its components.'

        value 'HEALTHY', description: 'Works as expected.', value: 'healthy'
        value 'DEGRADED', description: 'Works with reduced capacity.', value: 'degraded'
        value 'UNHEALTHY', description: 'Does not work.', value: 'unhealthy'
        value 'MIGRATING', description: 'Schema migration is in progress.', value: 'migrating'
        value 'UNKNOWN', description: 'Health is unknown, for example because Orbit is unreachable.',
          value: 'unknown'
      end
    end
  end
end
