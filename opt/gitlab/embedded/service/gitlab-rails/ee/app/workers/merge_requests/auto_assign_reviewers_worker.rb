# frozen_string_literal: true

module MergeRequests
  class AutoAssignReviewersWorker
    include ApplicationWorker

    idempotent!
    data_consistency :sticky
    urgency :low
    feature_category :code_review_workflow
    defer_on_database_health_signal :gitlab_main

    def perform(merge_request_id)
      merge_request = MergeRequest.find_by_id(merge_request_id)
      return unless merge_request
      return unless merge_request.reviewer_auto_assignment_enabled?
      return if merge_request.draft?
      return if non_automated_reviewers_present?(merge_request)

      ReviewerAssignment::AssignService.new(
        merge_request: merge_request,
        current_user: merge_request.author
      ).execute
    end

    private

    # Skip when a human reviewer is already set, but treat a lone Duo Code Review
    # bot as "no reviewer yet" so auto-assignment still runs alongside it.
    def non_automated_reviewers_present?(merge_request)
      reviewers = merge_request.reviewers
      return false if reviewers.empty?
      return false if reviewers.size == 1 && reviewers.first.duo_code_review_bot?

      true
    end
  end
end
