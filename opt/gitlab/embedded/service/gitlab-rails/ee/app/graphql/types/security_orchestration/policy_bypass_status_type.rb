# frozen_string_literal: true

module Types
  module SecurityOrchestration
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled in the resolver
    class PolicyBypassStatusType < BaseObject
      graphql_name 'PolicyBypassStatus'
      description 'Represents bypass status of a merge request for a security policy'

      field :id,
        type: GraphQL::Types::ID,
        null: false,
        description: 'ID of the security policy.'

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Name of the security policy.'

      field :allow_bypass,
        type: GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates if bypass is allowed for the policy.',
        extras: [:parent]

      field :bypassed,
        type: GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates if the policy has been bypassed.',
        extras: [:parent]

      def allow_bypass(parent:)
        object.merge_request_bypass_allowed?(parent, context[:current_user])
      end

      def bypassed(parent:)
        object.merge_request_bypassed?(parent)
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
