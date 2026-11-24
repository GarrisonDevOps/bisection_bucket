# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ItemConsumer
        module TriggerConditionsConverter
          def convert_trigger_conditions_to_h(trigger_conditions)
            trigger_conditions.to_h.transform_values { |group| convert_rule_group(group) }.as_json
          end

          private

          def convert_rule_group(group)
            group.slice(:match).merge(
              type: 'group',
              rules: group[:rules].map { |item| convert_rule_item(item) }
            )
          end

          def convert_rule_item(item)
            item.key?(:rules) || item.key?(:match) ? convert_rule_group(item) : convert_rule(item)
          end

          def convert_rule(rule)
            rule.slice(:field, :operator, :value)
          end
        end
      end
    end
  end
end
