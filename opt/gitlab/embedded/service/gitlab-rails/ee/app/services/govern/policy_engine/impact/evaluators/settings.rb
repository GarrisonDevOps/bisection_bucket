# frozen_string_literal: true

module Govern
  module PolicyEngine
    module Impact
      module Evaluators
        # Decides whether a project violates a set of setting_validation rules,
        # reading the same settings document the engine evaluates and applying
        # the same equality the compiled rule does. The caller has already
        # validated the rules through the store's transpiler.
        class Settings
          # Nil when a rule has no readable shape: an evaluator missing a rule would
          # read the whole set as compliant.
          def self.from_rules(rules)
            parsed = rules.map { |rule| ::Govern::PolicyEngine::SettingValidationRule.from_rule(rule) }
            return if parsed.any?(&:nil?)

            new(parsed)
          end

          def initialize(rules)
            @rules = rules
          end

          def preloads
            ProjectSettingsContext::PRELOAD_ASSOCIATIONS
          end

          def violates?(project)
            settings = ProjectSettingsContext.settings_for(project)

            rules.any? { |rule| violated?(rule, settings) }
          end

          private

          attr_reader :rules

          # The emitter strips the authored strings and reads through
          # `object.get(..., null)` with a `!= null` guard, so an absent key and a
          # stored NULL both stay compliant. A non-string setting name reaches here
          # only on an unvalidated draft; it names no key.
          def violated?(rule, settings)
            actual = settings[rule.setting.to_s.strip]
            return false if actual.nil?

            actual != (rule.expected.is_a?(String) ? rule.expected.strip : rule.expected)
          end
        end
      end
    end
  end
end
