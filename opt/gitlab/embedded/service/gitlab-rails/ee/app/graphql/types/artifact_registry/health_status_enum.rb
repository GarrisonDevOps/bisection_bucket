# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class HealthStatusEnum < BaseEnum
      graphql_name 'ArtifactRegistryHealthStatus'
      description 'Stored health verdict for a remote Artifact Registry repository upstream.'

      value 'UNKNOWN', value: 'unknown',
        description: 'No health probe has recorded a result yet, or Artifact Registry reported a status ' \
          'this schema does not recognize.'
      value 'HEALTHY', value: 'healthy', description: 'Most recent probe reached the upstream.'
      value 'UNHEALTHY', value: 'unhealthy',
        description: 'Consecutive probe failures reached the threshold Artifact Registry sets.'

      class << self
        # Absorbs a status this schema does not declare, which would otherwise fail
        # enum coercion and take the whole response with it. Shared by every path
        # that renders Artifact Registry's raw status.
        def recognized_or_unknown(status)
          enum.value?(status) ? status : enum[:unknown]
        end
      end
    end
  end
end
