# frozen_string_literal: true

module Integrations
  module SlackEvents
    class AgentDmService < AppMentionedService
      def execute
        return ServiceResponse.success if bot_message? || subtype_message?

        super
      end

      private

      def bot_message?
        slack_event[:bot_id].present?
      end

      def subtype_message?
        slack_event[:subtype].present?
      end
    end
  end
end
