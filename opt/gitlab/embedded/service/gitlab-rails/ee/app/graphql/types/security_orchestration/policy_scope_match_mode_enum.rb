# frozen_string_literal: true

module Types
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- Matches the existing GraphQL types
    class PolicyScopeMatchModeEnum < BaseEnum
      graphql_name 'PolicyScopeMatchMode'
      description 'Specifies how multiple policy scope conditions are combined.'

      value 'ALL',
        value: 'all',
        description: 'All specified conditions must match (AND logic). This is the default behavior.'

      value 'ANY',
        value: 'any',
        description: 'At least one specified condition must match (OR logic).'
    end
  end
end
