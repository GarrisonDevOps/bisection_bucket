# frozen_string_literal: true

module Ai
  module AiResource
    module Ci
      class Build < Ai::AiResource::BaseAiResource
        include Ai::AiResource::Concerns::Noteable

        CHAT_QUESTIONS = [
          "What errors or warnings appeared in this job?",
          "What caused any slow or failing steps in this job?",
          "Were all dependencies available in this job?",
          "What was each stage's final status?"
        ].freeze

        CHAT_UNIT_PRIMITIVE = :ask_build

        def serialize_for_ai(content_limit: default_content_limit)
          ::Ci::JobSerializer # rubocop: disable CodeReuse/Serializer -- existing serializer
            .new(current_user: current_user)
            .represent(resource, {
              user: current_user,
              content_limit: content_limit,
              resource: self
            }, ::Ci::JobAiEntity)
        end

        def current_page_type
          "build"
        end

        def current_page_params
          {
            type: current_page_type
          }
        end
      end
    end
  end
end
