# frozen_string_literal: true

module Types
  module Cd
    class RolloutTransitionStateEnum < BaseEnum
      graphql_name 'CdRolloutTransitionState'
      description 'State recorded in a continuous deployment rollout transition.'

      ::Cd::RolloutTransition::STATES.each_key do |state|
        value state.to_s.upcase, value: state.to_s, description: "Rollout transition state #{state.to_s.tr('_', ' ')}."
      end
    end
  end
end
