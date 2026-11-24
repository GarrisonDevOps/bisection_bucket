# frozen_string_literal: true

module Types
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- Existing module
    class PolicyViolationsEnum < BaseEnum
      graphql_name 'PolicyViolations'

      value 'DISMISSED_IN_MR',
        description: 'Dismissed in Merge request bypass reason.',
        value: :dismissed_in_mr
    end
  end
end
