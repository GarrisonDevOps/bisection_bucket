# frozen_string_literal: true

module Resolvers
  module Ai
    module Conversations
      class ThreadsResolver < BaseResolver
        type Types::Ai::Conversations::ThreadType, null: false

        argument :conversation_type, Types::Ai::Conversations::Threads::ConversationTypeEnum,
          required: false,
          description: 'Conversation type of the thread.'

        argument :id, ::Types::GlobalIDType[::Ai::Conversation::Thread],
          required: false,
          description: 'Id of the thread.'

        def resolve(**args)
          return [] unless current_user

          args[:id] = args[:id].model_id if args[:id]

          ::Ai::Conversations::ThreadFinder.new(current_user, args).execute
        end
      end
    end
  end
end
