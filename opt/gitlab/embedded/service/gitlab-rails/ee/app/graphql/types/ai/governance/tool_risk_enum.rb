# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class ToolRiskEnum < BaseEnum
        graphql_name 'AiGovernanceToolRisk'
        description 'Risk level of a tool, taken from its action type in the tool registry.'

        value 'READ', value: :read, description: 'Tools that only read data.'
        value 'WRITE', value: :write, description: 'Tools that create or change data.'
        value 'DESTROY', value: :destroy,
          description: 'Tools that can make destructive changes, such as running commands or Git.'
        value 'UNCLASSIFIED', value: :unclassified, description: 'Tools not found in the tool registry.'
      end
    end
  end
end
