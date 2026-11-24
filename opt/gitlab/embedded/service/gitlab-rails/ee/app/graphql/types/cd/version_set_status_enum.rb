# frozen_string_literal: true

module Types
  module Cd
    class VersionSetStatusEnum < BaseEnum
      graphql_name 'CdVersionSetStatus'
      description 'High-level lifecycle status of a continuous deployment release (version set).'

      value 'DEPLOYING', value: 'deploying', description: 'Release has a rollout currently in progress.'
      value 'SUPERSEDED', value: 'superseded',
        description: 'Release has been replaced, in at least one environment, by a newer release.'
      value 'ROLLED_BACK', value: 'rolled_back',
        description: 'Release was redeployed to an environment after a newer release had already run there.'
    end
  end
end
