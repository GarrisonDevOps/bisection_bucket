# frozen_string_literal: true

module Types
  module Govern
    class PolicyEvaluationTriggerTypeEnum < BaseEnum
      graphql_name 'GovernPolicyEvaluationTriggerType'
      description 'Trigger that started a policy evaluation.'

      ::Govern::PolicyEvaluation.trigger_types.each_key do |trigger_type|
        value trigger_type.tr('.', '_').upcase,
          value: trigger_type,
          description: "Evaluation was triggered by the `#{trigger_type}` operation."
      end
    end
  end
end
