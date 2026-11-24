# frozen_string_literal: true

module Govern
  module PolicyEngine
    # One authored setting_validation rule, as the Policy Store persists it:
    # { "type": "setting_validation", "value": { "setting":, "value": } }.
    # The key names appear here only. A custom Rego rule has no such shape,
    # so from_rule returns nil for it.
    class SettingValidationRule
      TYPE = ::Gitlab::PolicyStore::Rules::SETTING_VALIDATION

      TYPE_KEY = 'type'
      VALUE_KEY = 'value'
      SETTING_KEY = 'setting'
      REQUIRED_VALUE_KEY = 'value'

      attr_reader :setting, :expected

      def self.for_policy(policy)
        policy.rules.to_a.filter_map { |rule| from_rule(rule) }
      end

      def self.from_rule(rule)
        return unless rule[TYPE_KEY] == TYPE

        value = rule[VALUE_KEY]
        return unless value.is_a?(Hash) && value[SETTING_KEY].present?

        new(value[SETTING_KEY], value[REQUIRED_VALUE_KEY])
      end

      def initialize(setting, expected)
        @setting = setting
        @expected = expected
      end
    end
  end
end
