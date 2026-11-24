# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class PendingToolApproval
      FINGERPRINT_LENGTH = 16

      # The trailing run of consecutive request entries is the set of tool calls
      # the paused session is waiting on; a single decision resumes them all,
      # mirroring agentic web chat.
      def self.for(workflow)
        from_log(workflow.latest_ui_chat_log)
      end

      def self.from_log(log)
        requests = []
        log.reverse_each do |message|
          break unless message['message_type'] == 'request' && message['tool_info'].is_a?(Hash)

          requests.unshift(message)
        end

        return if requests.empty? || requests.any? { |request| request['message_id'].blank? }

        new(requests)
      end

      def initialize(requests)
        @requests = Array.wrap(requests)
      end

      def tool_names
        requests.map { |request| request.dig('tool_info', 'name').to_s }
      end

      def calls
        requests.map do |request|
          {
            name: request.dig('tool_info', 'name').to_s,
            content: request['content'],
            args: request.dig('tool_info', 'args') || {}
          }
        end
      end

      def fingerprint
        material = requests.map { |request| request.fetch('message_id') }

        Digest::SHA256.hexdigest(material.join("\x01")).first(FINGERPRINT_LENGTH)
      end

      private

      attr_reader :requests
    end
  end
end
