# frozen_string_literal: true

module MergeRequests
  class DestroyRequestedChangesService < ::MergeRequests::BaseService
    def execute(merge_request)
      return error('Invalid permissions') unless can?(current_user, :create_merge_request_review, merge_request)
      return error('Invalid license') unless merge_request.reviewer_requests_changes_feature

      if merge_request.requested_changes_for_users(current_user).any?
        merge_request.destroy_requested_changes(current_user)
        merge_request.batch_update_reviewer_state([current_user.id], :unreviewed)

        trigger_merge_request_reviewers_updated(merge_request)
        trigger_merge_request_merge_status_updated(merge_request)

        invalidate_cache_counts(merge_request, users: merge_request.assignees)
        invalidate_cache_counts(merge_request, users: merge_request.reviewers)

        current_user.invalidate_merge_request_cache_counts

        success
      else
        error('User has not requested changes for this merge request')
      end
    end
  end
end
