# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class AssignMergeRequestReview
          TEMPLATE = <<~GOAL.strip
            @%{triggered_by_username} requested your review on a merge request: %{resource_url}

            Fetch the merge request details and its diffs. Review the code changes thoroughly — check for correctness, potential bugs, readability, and adherence to the project's coding conventions. Read relevant existing code for context where needed.

            Leave your review as comments on the merge request, highlighting any issues found and suggesting improvements. Where appropriate, use GitLab suggestion blocks (```suggestion) in line comments so the author can apply fixes directly. If the changes look good, leave a comment summarizing your review — do not approve the merge request.

            When you have finished your review, @mention @%{triggered_by_username} in a comment to notify them that your review is complete.
          GOAL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, params:, **_)
            {
              resource_url: Gitlab::UrlBuilder.build(resource),
              triggered_by_username: params[:triggered_by_username].to_s
            }
          end
        end
      end
    end
  end
end
