# frozen_string_literal: true

module Types
  module Cd
    class RolloutStatusEnum < BaseEnum
      graphql_name 'CdRolloutStatus'
      description 'High-level status of a continuous deployment rollout.'

      value 'ACTIVE', value: 'active', description: 'Rollout is pending, in progress, or paused.'
      value 'SUCCEEDED', value: 'succeeded', description: 'Rollout finished successfully.'
      value 'FAILED', value: 'failed', description: 'Rollout finished unsuccessfully (failed or cancelled).'
    end
  end
end
