# frozen_string_literal: true

module Types
  module Govern
    class PolicyEvaluationVerdictEnum < BaseEnum
      graphql_name 'GovernPolicyEvaluationVerdict'
      description 'Verdict a policy evaluation produced.'

      ::Govern::PolicyEvaluation.verdicts.each_key do |verdict|
        value verdict.upcase,
          value: verdict,
          description: "Evaluation produced a `#{verdict}` verdict."
      end
    end
  end
end
