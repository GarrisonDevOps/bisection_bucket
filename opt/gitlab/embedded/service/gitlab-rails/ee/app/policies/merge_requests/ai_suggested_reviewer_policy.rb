# frozen_string_literal: true

module MergeRequests
  class AiSuggestedReviewerPolicy < ::BasePolicy
    delegate { @subject.user }
  end
end
