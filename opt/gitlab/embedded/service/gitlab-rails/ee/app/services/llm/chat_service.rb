# frozen_string_literal: true

module Llm
  class ChatService < BaseService
    include Gitlab::InternalEventsTracking

    private

    def ai_action
      :chat
    end

    def perform
      track_internal_event(
        'request_duo_chat_response',
        user: user,
        project: project,
        namespace: namespace,
        feature_enabled_by_namespace_ids: user.allowed_by_namespace_ids(:chat, unit_primitive_name: :duo_classic_chat)
      )

      prompt_message.save!
      GraphqlTriggers.ai_completion_response(prompt_message)

      schedule_completion_worker unless prompt_message.conversation_reset? || prompt_message.clear_history?
    end

    def content(_action_name)
      options[:content]
    end

    def user_can_send_to_ai?
      ::Gitlab::Llm::Chain::Utils::ChatAuthorizer.user(user: user).allowed?
    end

    def agent_not_found_message
      _('Agent not found for provided id.')
    end

    def insufficient_agent_permission_message
      _('User does not have permission to modify agent.')
    end
  end
end
