# frozen_string_literal: true

module Gitlab
  module Llm
    class ThreadEnsurer
      LEGACY_CONVERSATION_TYPE = :duo_chat_legacy

      def initialize(user)
        @base_thread_relation = user.ai_conversation_threads
      end

      def execute(thread_id: nil, conversation_type: nil, write_mode: false)
        if thread_id.nil? && conversation_type.nil?
          ensure_legacy_thread
        elsif thread_id
          find_thread(thread_id)
        elsif write_mode
          create_thread(conversation_type)
        else # read_mode
          thread = last_thread(conversation_type)

          if thread
            thread
          elsif conversation_type == LEGACY_CONVERSATION_TYPE
            create_thread(LEGACY_CONVERSATION_TYPE)
          end
        end
      end

      private

      attr_reader :base_thread_relation

      def find_thread(thread_id)
        return unless thread_id

        base_thread_relation.find(thread_id)
      rescue ActiveRecord::RecordNotFound
        raise "Thread not found. It may have expired."
      end

      def create_thread(conversation_type)
        return unless conversation_type

        base_thread_relation.create!(conversation_type: conversation_type)
      rescue ActiveRecord::RecordNotSaved, ArgumentError
        raise "Failed to create a thread for #{conversation_type}."
      end

      def last_thread(conversation_type)
        base_thread_relation.for_conversation_type(conversation_type).last
      end

      def ensure_legacy_thread
        last_thread(LEGACY_CONVERSATION_TYPE) || create_thread(LEGACY_CONVERSATION_TYPE)
      end
    end
  end
end
