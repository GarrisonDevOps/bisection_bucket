# frozen_string_literal: true

module Llm
  module Internal
    class CategorizeChatQuestionService < BaseService
      extend ::Gitlab::Utils::Override

      private

      def perform
        schedule_completion_worker
      end

      def ai_action
        :categorize_question
      end

      override :user_can_send_to_ai?
      def user_can_send_to_ai?
        # only performed on .com
        return false unless ::Gitlab.com? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- internal tool

        user.allowed_to_use?(:duo_chat)
      end
    end
  end
end
