# frozen_string_literal: true

module Types
  module Ai
    module Conversations
      module Threads
        class ConversationTypeEnum < BaseEnum
          graphql_name 'AiConversationsThreadsConversationType'
          description 'Conversation type of the thread.'

          ::Ai::Conversation::Thread.conversation_types.each_key do |conv_type|
            value conv_type.upcase, description: "#{conv_type} thread.", value: conv_type
          end
        end
      end
    end
  end
end
