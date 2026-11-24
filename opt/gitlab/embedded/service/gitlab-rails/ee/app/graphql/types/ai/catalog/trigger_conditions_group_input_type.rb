# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class TriggerConditionsGroupInputType < BaseInputObject
        graphql_name 'AiCatalogTriggerConditionsGroupInput'
        description 'Group of rules for a set of trigger conditions.'

        argument :match, ::Types::Ai::Catalog::TriggerConditionsMatchEnum,
          required: false,
          description: 'Strategy used to match the rules in the group.'

        argument :rules, [::Types::Ai::Catalog::TriggerConditionsRuleItemInputType],
          required: true,
          description: 'Rules in the group.'
      end
    end
  end
end
