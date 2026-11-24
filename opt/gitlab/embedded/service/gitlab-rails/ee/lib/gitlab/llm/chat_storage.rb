# frozen_string_literal: true

module Gitlab
  module Llm
    class ChatStorage
      include Gitlab::Utils::StrongMemoize

      POSTGRESQL_STORAGE = "postgresql"

      delegate :messages, :current_thread, :add, :clear!, to: :postgres_storage

      def initialize(user, thread = nil)
        @user = user
        @thread = thread
      end

      def messages_by(filters = {})
        messages.select do |message|
          matches_filters?(message, filters)
        end
      end

      def last_conversation
        self.class.last_conversation(messages)
      end

      def self.last_conversation(messages)
        idx = messages.rindex(&:conversation_reset?)
        return messages unless idx
        return [] unless idx + 1 < messages.size

        messages[idx + 1..]
      end

      def messages_up_to(message_id)
        all = messages
        idx = all.rindex { |m| m.message_xid == message_id }
        idx ? all.first(idx + 1) : []
      end

      private

      attr_reader :user, :thread

      def storage_class(type)
        "Gitlab::Llm::ChatStorage::#{type.camelize}".constantize
      end

      def matches_filters?(message, filters)
        return false if filters[:roles]&.exclude?(message.role)
        return false if filters[:request_ids]&.exclude?(message.request_id)

        true
      end

      def postgres_storage
        @postgres_storage ||= storage_class(POSTGRESQL_STORAGE)
          .new(user, thread)
      end
    end
  end
end
