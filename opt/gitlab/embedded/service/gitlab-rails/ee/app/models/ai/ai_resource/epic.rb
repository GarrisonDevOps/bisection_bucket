# frozen_string_literal: true

module Ai
  module AiResource
    class Epic < Ai::AiResource::BaseAiResource
      include Ai::AiResource::Concerns::Noteable

      CHAT_QUESTIONS = [
        "What is the objective and scope of this epic?",
        "What key features are planned?",
        "What are the main concerns from discussions?",
        "What is the current progress and implementation status?"
      ].freeze

      CHAT_UNIT_PRIMITIVE = :ask_epic

      def serialize_for_ai(content_limit: default_content_limit)
        ::EpicSerializer.new(current_user: current_user) # rubocop: disable CodeReuse/Serializer -- serializes the epic for the chat prompt
                        .represent(resource, {
                          user: current_user,
                          notes_limit: content_limit,
                          serializer: 'ai',
                          resource: self
                        })
      end

      def current_page_type
        "epic"
      end
    end
  end
end
