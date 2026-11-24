# frozen_string_literal: true

module Types
  module Cd
    class DeploymentStateEnum < BaseEnum
      graphql_name 'CdDeploymentState'
      description 'State of a continuous deployment deployment.'

      ::Cd::Deployment.states.each_key do |state|
        value state.upcase, value: state, description: "Deployment is #{state.tr('_', ' ')}."
      end
    end
  end
end
