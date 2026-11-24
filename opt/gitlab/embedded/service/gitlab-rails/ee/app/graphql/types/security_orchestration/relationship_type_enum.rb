# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class RelationshipTypeEnum < BaseEnum
      graphql_name 'RelationshipType'
      description 'Relationship of the policies to resync.'

      value 'DIRECT',
        description: 'Policies defined for the project/group only.',
        value: :direct

      value 'INHERITED',
        description: 'Policies defined for the project/group and ancestor groups.',
        value: :inherited
    end
  end
end
