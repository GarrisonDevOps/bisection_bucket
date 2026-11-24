# frozen_string_literal: true

module Govern
  module PolicyEngine
    module Impact
      # Picks the evaluator for a rule set. Every rule kind the host can analyse
      # without the engine registers here; a rule set that mixes kinds, or uses
      # one with no evaluator, has no host-side answer and yields nil.
      module Evaluators
        TYPE_KEY = 'type'

        def self.for(rules)
          types = rules.map { |rule| rule.is_a?(Hash) ? rule[TYPE_KEY] : nil }.uniq
          return unless types.size == 1

          evaluator_class(types.first)&.from_rules(rules)
        end

        def self.evaluator_class(type)
          Settings if type == ::Govern::PolicyEngine::SettingValidationRule::TYPE
        end
        private_class_method :evaluator_class
      end
    end
  end
end
