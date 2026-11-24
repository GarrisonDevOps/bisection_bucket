# frozen_string_literal: true

module Types
  module Cd
    class RolloutEnvironmentStateEnum < BaseEnum
      graphql_name 'CdRolloutEnvironmentState'
      description 'State of a continuous deployment rollout environment.'

      ::Cd::RolloutEnvironment.states.each_key do |state|
        value state.upcase, value: state, description: "Rollout environment is #{state.tr('_', ' ')}."
      end
    end
  end
end
