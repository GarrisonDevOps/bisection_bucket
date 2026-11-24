# frozen_string_literal: true

module Ai
  module AiResource
    class MergeRequest < Ai::AiResource::BaseAiResource
      include Ai::AiResource::Concerns::Noteable

      CHAT_QUESTIONS = [
        "What are the main points from this MR discussion?",
        "What changes were requested by reviewers?",
        "What concerns remain unresolved in this MR?",
        "What changed in this diff?"
      ].freeze

      CHAT_UNIT_PRIMITIVE = :ask_merge_request

      def serialize_for_ai(content_limit: default_content_limit, is_duo_code_review: false)
        ::MergeRequestSerializer.new(current_user: current_user) # rubocop: disable CodeReuse/Serializer -- existing serializer
                        .represent(resource, {
                          user: current_user,
                          notes_limit: content_limit,
                          serializer: 'ai',
                          resource: self,
                          is_duo_code_review: is_duo_code_review
                        })
      end

      def current_page_type
        "merge_request"
      end
    end
  end
end
