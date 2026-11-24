# frozen_string_literal: true

module Gitlab
  module Llm
    class ChatMessage < AiMessage
      RESET_MESSAGE = '/reset'
      CLEAR_HISTORY_MESSAGE = '/clear'
      NEW_MESSAGE = '/new'

      attr_writer :active_record

      alias_method :message_xid, :id

      def save!
        storage = ChatStorage.new(user, thread)

        if clear_history?
          storage.clear!
        else
          @active_record = storage.add(self)
        end

        self.thread = storage.current_thread
      end

      def conversation_reset?
        content == RESET_MESSAGE
      end

      def clear_history?
        content == CLEAR_HISTORY_MESSAGE || content == NEW_MESSAGE
      end

      def question?
        user? && !conversation_reset? && !clear_history?
      end

      def active_record
        @active_record ||= ::Ai::Conversation::Message.for_user(user).for_id(id).first
      end

      def chat?
        true
      end
    end
  end
end
