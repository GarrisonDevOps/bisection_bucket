# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class SecurityPolicyRelationTypeEnum < BaseEnum
      graphql_name 'SecurityPolicyRelationType'

      value 'DIRECT',
        description: 'Policies defined for the project/group only.',
        value: :direct

      value 'INHERITED',
        description: 'Policies defined for the project/group and ancestor groups.',
        value: :inherited

      value 'INHERITED_ONLY',
        description: 'Policies defined for the project/group\'s ancestor groups only.',
        value: :inherited_only

      value 'DESCENDANT',
        description: 'Policies defined for the group\'s descendant projects/groups only. ' \
          'Only valid for group policies. ' \
          'Policies apply only to the 50 most recently created descendant policy projects.',
        value: :descendant
    end
  end
end
