# frozen_string_literal: true

module Types
  module Cd
    class RolloutStateEnum < BaseEnum
      graphql_name 'CdRolloutState'
      description 'State of a continuous deployment rollout.'

      ::Cd::Rollout.states.each_key do |state|
        value state.upcase, value: state, description: "Rollout is #{state.tr('_', ' ')}."
      end
    end
  end
end
