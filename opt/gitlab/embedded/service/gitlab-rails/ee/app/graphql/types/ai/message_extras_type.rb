# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- only reachable through AiMessage, which is scoped to the current user
    class MessageExtrasType < Types::BaseObject
      graphql_name 'AiMessageExtras'
      description "Extra metadata for AI message."

      def self.authorization_scopes
        [:api, :read_api, :ai_features]
      end

      field :sources, [GraphQL::Types::JSON],
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: "Sources used to form the message."

      field :has_feedback, GraphQL::Types::Boolean,
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: "Whether the user has provided feedback for the message."

      field :additional_context,
        [Types::Ai::AdditionalContextType],
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Additional context for the message.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
