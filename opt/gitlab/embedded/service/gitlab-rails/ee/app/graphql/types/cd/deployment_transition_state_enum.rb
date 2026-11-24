# frozen_string_literal: true

module Types
  module Cd
    class DeploymentTransitionStateEnum < BaseEnum
      graphql_name 'CdDeploymentTransitionState'
      description 'State recorded in a continuous deployment deployment transition.'

      ::Cd::DeploymentTransition::STATES.each_key do |state|
        value state.to_s.upcase, value: state.to_s,
          description: "Deployment transition state #{state.to_s.tr('_', ' ')}."
      end
    end
  end
end
