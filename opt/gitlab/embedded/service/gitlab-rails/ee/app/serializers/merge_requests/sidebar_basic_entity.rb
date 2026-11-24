# frozen_string_literal: true

module MergeRequests
  class SidebarBasicEntity < IssuableSidebarBasicEntity
    expose :multiple_approval_rules_available do |merge_request|
      merge_request.target_project.multiple_approval_rules_available?
    end

    expose :ai_suggested_reviewers_available do |merge_request|
      ::Gitlab::Duo::RecommendReviewers.available?(merge_request.target_project)
    end
  end
end
