# frozen_string_literal: true

module Types
  module Cd
    class ApplicationStatusEnum < BaseEnum
      graphql_name 'CdApplicationStatus'
      description 'Status used to filter the continuous deployment applications list. ' \
        'An application can match more than one status.'

      value 'HEALTHY', value: 'healthy',
        description: 'Worst service health across the application is healthy.'
      value 'DEGRADED', value: 'degraded',
        description: 'Worst service health across the application is degraded.'
      value 'DEPLOYING', value: 'deploying',
        description: 'Application has a rollout in progress.'
      value 'AWAITING_APPROVAL', value: 'awaiting_approval',
        description: 'Application has a rollout waiting on an approval. ' \
          'Not recorded on the backend yet, so this always matches no applications for now.'
    end
  end
end
