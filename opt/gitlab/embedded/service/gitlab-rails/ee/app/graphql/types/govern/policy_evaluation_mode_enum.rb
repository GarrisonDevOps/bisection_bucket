# frozen_string_literal: true

module Types
  module Govern
    class PolicyEvaluationModeEnum < BaseEnum
      graphql_name 'GovernPolicyEvaluationMode'
      description 'Enforcement mode of the policy at the time of an evaluation.'

      ::Govern::PolicyEvaluation.modes.each_key do |mode|
        value mode.upcase,
          value: mode,
          description: "Policy was in `#{mode}` mode when it was evaluated."
      end
    end
  end
end
