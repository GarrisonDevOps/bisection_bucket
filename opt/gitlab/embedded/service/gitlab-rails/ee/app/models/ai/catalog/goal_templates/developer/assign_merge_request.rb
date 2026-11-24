# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class AssignMergeRequest
          TEMPLATE = <<~GOAL.strip
            @%{triggered_by_username} assigned you to a merge request: %{resource_url}

            Fetch the merge request details, its diffs, pipeline status, and any review comments or discussions. Understand the current state of the merge request and determine what action is needed — this could be fixing failing pipelines, addressing review feedback, resolving discussions, or continuing implementation work.

            If the required action is not clear from the context, leave a comment asking for clarification on what is expected.

            When you have completed your work, @mention @%{triggered_by_username} in a comment to notify them.
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
