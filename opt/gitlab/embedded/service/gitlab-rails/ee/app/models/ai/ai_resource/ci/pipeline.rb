# frozen_string_literal: true

module Ai
  module AiResource
    module Ci
      class Pipeline < Ai::AiResource::BaseAiResource
        CHAT_QUESTIONS = [].freeze
        CHAT_UNIT_PRIMITIVE = :duo_chat

        # Pipeline data is small and structured, no content limiting needed.
        def serialize_for_ai(**)
          project = resource.project

          {
            id: resource.id,
            iid: resource.iid,
            ref: resource.ref,
            sha: resource.sha,
            source: resource.source,
            status: resource.status,
            project_full_path: project&.full_path,
            web_url: project ? ::Gitlab::Routing.url_helpers.project_pipeline_url(project, resource) : nil,
            created_at: resource.created_at&.iso8601,
            source_ref: resource.source_ref
          }
        end

        def current_page_type
          "pipeline"
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
