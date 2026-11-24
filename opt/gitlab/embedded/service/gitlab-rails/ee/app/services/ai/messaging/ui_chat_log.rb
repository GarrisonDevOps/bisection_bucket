# frozen_string_literal: true

module Ai
  module Messaging
    # Reads the flow's own ui_chat_log format, so the adapters that render live
    # progress cannot drift from each other as that format evolves.
    module UiChatLog
      def latest_todos(messages)
        todo_info = messages.reverse_each.detect { |m| todo_write?(m) }&.dig('tool_info')

        todo_info&.dig('args', 'todos') || []
      end

      def latest_agent_content(messages)
        messages
          .reverse_each
          .detect { |m| m['message_type'] == 'agent' && m['content'].present? }
          &.dig('content')
      end

      def renders_progress?(message)
        (message['message_type'] == 'agent' && message['content'].present?) ||
          todo_write?(message)
      end

      private

      # tool_info is absent on plain agent messages and has been seen as a string.
      def todo_write?(message)
        message['tool_info'].is_a?(Hash) && message['tool_info']['name'] == 'todo_write'
      end
    end
  end
end
