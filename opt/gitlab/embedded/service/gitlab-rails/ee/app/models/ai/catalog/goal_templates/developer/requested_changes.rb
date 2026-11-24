# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class RequestedChanges
          # The reviewer's name is never an @-mention: a mention of GitLab Duo starts a Duo Code Review chat.
          TEMPLATE = <<~GOAL.strip
            The reviewer %{reviewer_username} requested changes on the merge request %{resource_url}.
            Respond to the review the way a good engineer would: address the feedback, make sure your changes do not break the pipeline, and leave the merge request ready for the next review.

            - Work only on this merge request and push to its source branch.
            - For each unresolved thread that %{reviewer_username} started, change the code or decide that no change is needed, and reply in the thread with what you did and why. Do not resolve the threads.
            - Fix pipeline failures that this merge request causes. Leave failures that it does not cause, and explain them in one note on the merge request.
            - Push all fixes in one push: each push starts a new review and a new pipeline, which the next cycle picks up. So do not wait for, retry, or cancel pipelines.
            - Do not change the title, labels, or draft state, and do not @-mention anyone, including %{reviewer_username}. The review loop depends on these.
          GOAL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, params:, **_)
            {
              resource_url: Gitlab::UrlBuilder.build(resource),
              reviewer_username: params[:reviewer_username].to_s
            }
          end
        end
      end
    end
  end
end
