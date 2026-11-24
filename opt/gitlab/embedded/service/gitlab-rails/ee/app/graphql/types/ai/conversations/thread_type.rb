# frozen_string_literal: true

module Types
  module Ai
    module Conversations
      # rubocop:disable Graphql/AuthorizeTypes -- Threads are user-specific resources
      class ThreadType < Types::BaseObject
        graphql_name 'AiConversationsThread'
        description "Conversation thread of the AI feature"

        field :id,
          GraphQL::Types::ID,
          null: false,
          description: 'ID of the thread.'

        field :last_updated_at,
          Types::TimeType,
          null: false,
          description: 'Last updated date of the thread.'

        field :created_at,
          Types::TimeType,
          null: false,
          description: 'Created date of the thread.'

        field :conversation_type,
          Types::Ai::Conversations::Threads::ConversationTypeEnum,
          null: false,
          description: 'Conversation type of the thread.'

        field :title,
          GraphQL::Types::String,
          resolver: ::Resolvers::Ai::Conversations::TitleResolver,
          null: true,
          description: 'Title of the thread.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
