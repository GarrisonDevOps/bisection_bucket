# frozen_string_literal: true

module Members
  module UnassignIssuables
    class MergeRequestsService < BaseService
      private

      def assignee_class
        MergeRequestAssignee
      end

      def id_column
        :merge_request_id
      end

      def payload(processed:, skipped:, still_assigned:)
        {
          processed_merge_requests_count: processed,
          skipped_merge_requests_count: skipped,
          still_assigned_merge_requests_count: still_assigned
        }
      end

      def issuable_for(assignee)
        assignee.merge_request
      end

      def save_assignees(merge_request, assignee_ids)
        ::MergeRequests::UpdateAssigneesService.new(
          project: merge_request.project, current_user: requesting_user, params: { assignee_ids: assignee_ids }
        ).execute(merge_request)
      end
    end
  end
end
