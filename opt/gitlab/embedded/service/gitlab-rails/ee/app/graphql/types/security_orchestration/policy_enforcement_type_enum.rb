# frozen_string_literal: true

module Types
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- Matches the existing GraphQL types
    class PolicyEnforcementTypeEnum < BaseEnum
      graphql_name 'PolicyEnforcementType'

      value 'ENFORCE',
        value: 'enforce',
        description: 'Represents an enforced policy type.'

      value 'WARN',
        value: 'warn',
        description: 'Represents a warn mode policy type.'
    end
  end
end
