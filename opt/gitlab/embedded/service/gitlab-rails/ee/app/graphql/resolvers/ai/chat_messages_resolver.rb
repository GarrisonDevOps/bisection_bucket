# frozen_string_literal: true

module Resolvers
  module Ai
    class ChatMessagesResolver < BaseResolver
      type Types::Ai::MessageType, null: false

      argument :request_ids, [GraphQL::Types::ID],
        required: false,
        description: 'Array of request IDs to fetch.'

      argument :roles, [Types::Ai::MessageRoleEnum],
        required: false,
        description: 'Array of roles to fetch.'

      argument :conversation_type, Types::Ai::Conversations::Threads::ConversationTypeEnum,
        required: false,
        description: 'Conversation type of the thread.'

      argument :thread_id,
        ::Types::GlobalIDType[::Ai::Conversation::Thread],
        required: false,
        description: 'Global Id of the existing thread.' \
          'If it is not specified, the last thread for the specified conversation_type will be retrieved.'

      def resolve(**args)
        return [] unless current_user

        thread = find_thread(args)

        ::Gitlab::Llm::ChatStorage.new(current_user, thread).messages_by(args)
      end

      private

      def find_thread(args)
        thread_id = args[:thread_id]&.model_id
        Gitlab::Llm::ThreadEnsurer.new(current_user).execute(
          thread_id: thread_id,
          conversation_type: args[:conversation_type]
        )
      rescue RuntimeError => e
        raise Gitlab::Graphql::Errors::ArgumentError, e.message
      end
    end
  end
end
