# frozen_string_literal: true

module Types
  module Security
    class PolicyDismissalType < BaseObject
      graphql_name 'PolicyDismissal'
      description 'Represents a policy dismissal for a security finding or license occurrence'

      authorize :read_security_resource

      field :id, GraphQL::Types::ID,
        null: false,
        description: 'ID of the policy dismissal.'

      field :security_policy, Types::Security::PolicyType,
        null: true,
        description: 'Security policy associated with the dismissal.'
    end
  end
end
