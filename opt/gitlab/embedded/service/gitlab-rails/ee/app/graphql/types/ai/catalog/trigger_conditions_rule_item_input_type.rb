# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class TriggerConditionsRuleItemInputType < BaseInputObject
        graphql_name 'AiCatalogTriggerConditionsRuleItemInput'
        description 'Item within a trigger conditions group. Provide either the rule fields ' \
          '(`field`, `operator`, `value`) or `rules` for a nested group, but not both. ' \
          '`match` can only be provided with `rules`.'

        argument :field, GraphQL::Types::String,
          required: false,
          description: 'Field the rule applies to.'

        argument :operator, ::Types::Ai::Catalog::TriggerConditionsOperatorEnum,
          required: false,
          description: 'Operator used to compare the field to the value.'

        argument :value, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- rule value is unconstrained in the filter JSON schema
          required: false,
          description: 'Value to compare the field against.'

        argument :match, ::Types::Ai::Catalog::TriggerConditionsMatchEnum,
          required: false,
          description: 'Strategy used to match the rules in the nested group.'

        argument :rules, [-> { ::Types::Ai::Catalog::TriggerConditionsRuleItemInputType }],
          required: false,
          description: 'Rules in the nested group.'

        validates required: { one_of: [%i[field operator value], %i[rules]] }

        # `match` is optional for a group (it defaults to `all` when evaluated), so it cannot be part of the
        # `one_of` set above and would otherwise pass validation alongside a rule.
        validates mutually_exclusive: [:match, :field]
        validates mutually_exclusive: [:match, :operator]
        validates mutually_exclusive: [:match, :value]
      end
    end
  end
end
