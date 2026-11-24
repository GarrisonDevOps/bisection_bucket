# frozen_string_literal: true

module Members
  module UnassignIssuables
    class IssuesService < BaseService
      private

      def assignee_class
        IssueAssignee
      end

      def id_column
        :issue_id
      end

      def payload(processed:, skipped:, still_assigned:)
        {
          processed_issues_count: processed,
          skipped_issues_count: skipped,
          still_assigned_issues_count: still_assigned
        }
      end

      def issuable_for(assignee)
        assignee.issue
      end

      def save_assignees(issue, assignee_ids)
        Issues::UpdateService.new(
          container: issue.project, current_user: requesting_user, params: { assignee_ids: assignee_ids }
        ).execute_without_rate_limiting(issue)
      end
    end
  end
end
