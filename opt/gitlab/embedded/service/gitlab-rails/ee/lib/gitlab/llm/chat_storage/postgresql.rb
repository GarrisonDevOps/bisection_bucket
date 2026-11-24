# frozen_string_literal: true

module Gitlab
  module Llm
    class ChatStorage
      class Postgresql < Base
        DEFAULT_CONVERSATION_TYPE = :duo_chat_legacy
        MAX_MESSAGES = 50

        def add(message)
          raise 'thread_absent' unless current_thread

          # Message is stored only partially. Some data might be missing after reloading from storage.
          data = message.to_h.slice(*%w[role referer_url])

          extras = message.extras
          if message.additional_context.present?
            extras ||= {}
            extras['additional_context'] = message.additional_context.to_a
          end

          data['extras'] = extras.to_json if extras
          data['content'] = message.content[0, MAX_TEXT_LIMIT] if message.content
          data['message_xid'] = message.id if message.id
          data['error_details'] = message.errors.to_json if message.errors
          data['request_xid'] = message.request_id if message.request_id

          data.compact!

          result = current_thread.messages.create!(**data)
          current_thread.update_column(:last_updated_at, Time.current)
          clear_memoization(:messages)

          result
        end

        def messages
          return [] unless current_thread

          current_thread.messages.recent(MAX_MESSAGES)
        end
        strong_memoize_attr :messages

        def clear!
          raise 'thread_absent' unless current_thread

          @current_thread = current_thread.to_new_thread!
          clear_memoization(:messages)
        end

        def current_thread
          @current_thread ||= thread
        end
      end
    end
  end
end
