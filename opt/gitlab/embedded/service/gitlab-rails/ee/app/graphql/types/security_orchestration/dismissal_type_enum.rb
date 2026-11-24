# frozen_string_literal: true

module Types
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- module already exists and holds the other types as well
    class DismissalTypeEnum < BaseEnum
      graphql_name 'DismissalType'
      description 'Represents the different dismissal types for security policy violations.'

      value 'POLICY_FALSE_POSITIVE',
        description: 'Dismissal due to policy false positive.',
        value: ::Security::PolicyDismissal::DISMISSAL_TYPES[:policy_false_positive]

      value 'SCANNER_FALSE_POSITIVE',
        description: 'Dismissal due to scanner false positive.',
        value: ::Security::PolicyDismissal::DISMISSAL_TYPES[:scanner_false_positive]

      value 'EMERGENCY_HOT_FIX',
        description: 'Dismissal due to emergency hot fix.',
        value: ::Security::PolicyDismissal::DISMISSAL_TYPES[:emergency_hot_fix]

      value 'OTHER',
        description: 'Dismissal due to other reasons.',
        value: ::Security::PolicyDismissal::DISMISSAL_TYPES[:other]
    end
  end
end
