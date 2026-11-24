# frozen_string_literal: true

module Ai
  module AiResource
    class Issue < Ai::AiResource::BaseAiResource
      include Ai::AiResource::Concerns::Noteable

      CHAT_QUESTIONS = [
        "What is the current state of this issue?",
        "What key decisions were made in this issue?",
        "Are there any concerns or blockers on this issue?",
        "What are the agreed next steps in this issue?"
      ].freeze

      CHAT_UNIT_PRIMITIVE = :ask_issue

      def serialize_for_ai(content_limit: default_content_limit)
        ::IssueSerializer.new(current_user: current_user, project: resource.project) # rubocop: disable CodeReuse/Serializer -- serializes the issue for the chat prompt
                         .represent(resource, {
                           user: current_user,
                           notes_limit: content_limit,
                           serializer: 'ai',
                           resource: self
                         })
      end

      def current_page_type
        "issue"
      end
    end
  end
end
