# frozen_string_literal: true

module EE
  class MergeRequestAiEntity < ::API::Entities::MergeRequest
    expose :diff do |mr, options|
      ::Gitlab::Llm::Utils::MergeRequestTool.extract_diff_for_duo_chat(
        merge_request: mr,
        character_limit: options[:notes_limit] / 2
      )
    end

    expose :mr_comments do |_mr, options|
      options[:resource].notes_with_limit(notes_limit: options[:notes_limit] / 2,
        is_duo_code_review: options[:is_duo_code_review])
    end
  end
end
