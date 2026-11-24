# frozen_string_literal: true

module Types
  module Cd
    class EnvironmentStatusEnum < BaseEnum
      graphql_name 'CdEnvironmentStatus'
      description 'Status used to filter the continuous deployment environments list. ' \
        'An environment can match more than one status.'

      value 'HEALTHY', value: 'healthy',
        description: 'Worst service health across the environment is healthy.'
      value 'DEGRADED', value: 'degraded',
        description: 'Worst service health across the environment is degraded or failed.'
      value 'DEPLOYING', value: 'deploying',
        description: 'Environment has a rollout in progress.'
    end
  end
end
