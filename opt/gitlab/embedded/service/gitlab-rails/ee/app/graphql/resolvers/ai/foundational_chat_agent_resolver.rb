# frozen_string_literal: true

module Resolvers
  module Ai
    class FoundationalChatAgentResolver < BaseResolver
      description 'AI foundational chat agent.'

      type ::Types::Ai::FoundationalChatAgentType, null: true

      argument :reference, GraphQL::Types::String,
        required: true,
        description: 'Reference to the foundational chat agent.'

      def resolve(reference:)
        ::Ai::FoundationalChatAgent.find_by_reference(reference)
      end
    end
  end
end
