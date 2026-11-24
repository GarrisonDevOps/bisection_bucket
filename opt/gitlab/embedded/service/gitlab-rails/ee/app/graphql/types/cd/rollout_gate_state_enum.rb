# frozen_string_literal: true

module Types
  module Cd
    class RolloutGateStateEnum < BaseEnum
      graphql_name 'CdRolloutGateState'
      description 'State of a continuous deployment rollout approval gate.'

      ::Cd::RolloutGate::STATES.each do |state|
        value state.to_s.upcase, value: state, description: "Rollout gate is #{state}."
      end
    end
  end
end
