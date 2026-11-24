# frozen_string_literal: true

module Types
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- Matches the existing GraphQL types
    class PolicyViolationStatusEnum < BaseEnum
      graphql_name 'PolicyViolationStatus'

      value 'FAILED',
        value: 'failed',
        description: 'Represents a failed policy violation.'

      value 'RUNNING',
        value: 'running',
        description: 'Represents a running policy violation.'

      value 'WARNING',
        value: 'warn',
        description: 'Represents a policy violation warning.'

      value 'SKIPPED',
        value: 'skipped',
        description: 'Represents a skipped policy violation.'
    end
  end
end
