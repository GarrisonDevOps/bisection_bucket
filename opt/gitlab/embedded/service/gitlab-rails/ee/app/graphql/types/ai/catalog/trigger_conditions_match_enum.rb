# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class TriggerConditionsMatchEnum < BaseEnum
        graphql_name 'AiCatalogTriggerConditionsMatch'
        description 'Match strategy for a trigger conditions group.'

        value 'ALL', description: 'All rules in the group must match.', value: 'all'
        value 'ANY', description: 'Any rule in the group must match.', value: 'any'
      end
    end
  end
end
