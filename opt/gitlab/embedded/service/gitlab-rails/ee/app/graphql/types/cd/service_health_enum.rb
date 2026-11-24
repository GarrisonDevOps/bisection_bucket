# frozen_string_literal: true

module Types
  module Cd
    class ServiceHealthEnum < BaseEnum
      graphql_name 'CdServiceHealth'
      description 'Observed health of a service in an environment.'

      ::Cd::ServiceEnvironmentHealth.healths.each_key do |health|
        value health.upcase, value: health, description: "Service is #{health.tr('_', ' ')}."
      end
    end
  end
end
