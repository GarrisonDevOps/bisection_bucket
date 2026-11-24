# frozen_string_literal: true

module Types
  module Cd
    class RolloutStepStateEnum < BaseEnum
      graphql_name 'CdRolloutStepState'
      description 'State of a continuous deployment rollout step.'

      ::Cd::RolloutStep.states.each_key do |state|
        value state.upcase, value: state, description: "Rollout step is #{state.tr('_', ' ')}."
      end
    end
  end
end
