# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyAnyMergeRequestViolationType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyAnyMergeRequestViolation'
      description 'Represents policy violation for `any_merge_request` report_type'

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Represents the policy name.'

      field :commits,
        type: GraphQL::Types::JSON,
        null: true,
        description: 'List of unsigned commits causing the violation. ' \
          'If policy targets any commits, it returns `true`.'
    end
  end
end
