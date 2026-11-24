# frozen_string_literal: true

module Ai
  module AiResource
    class Commit < Ai::AiResource::BaseAiResource
      include Ai::AiResource::Concerns::Noteable

      CHAT_QUESTIONS = [
        "What changes does this commit introduce?",
        "What files were modified in this commit?",
        "What is the impact of this commit?",
        "How can I test these changes?"
      ].freeze

      CHAT_UNIT_PRIMITIVE = :ask_commit

      def serialize_for_ai(content_limit: default_content_limit)
        EE::CommitSerializer # rubocop:disable CodeReuse/Serializer -- existing serializer
          .new(current_user: current_user, project: resource.project)
          .represent(resource, {
            user: current_user,
            notes_limit: content_limit,
            serializer: 'ai',
            resource: self
          })
      end

      def current_page_type
        "commit"
      end
    end
  end
end
