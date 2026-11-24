# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class FailedPipeline
          # The reviewer's name is never an @-mention: a mention of GitLab Duo starts a Duo Code Review chat.
          TEMPLATE = <<~GOAL.strip
            The reviewer %{reviewer_username} approved the merge request %{resource_url}, and its pipeline %{pipeline_url} failed.
            Fix the failures that this merge request causes, so that it is ready for the final review.

            - Work only on this merge request and push to its source branch.
            - Fix pipeline failures that this merge request causes. Leave failures that it does not cause, and explain them in one note on the merge request.
            - If this merge request causes none of the failures, do not push. The review loop then tells the author that the merge request is ready.
            - Push all fixes in one push: each push starts a new review and a new pipeline, which the next cycle picks up. So do not wait for, retry, or cancel pipelines.
            - Do not change the title, labels, or draft state, and do not @-mention anyone, including %{reviewer_username}. The review loop depends on these.
          GOAL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, params:, **_)
            {
              resource_url: Gitlab::UrlBuilder.build(resource),
              reviewer_username: params[:reviewer_username].to_s,
              pipeline_url: params[:pipeline_url].to_s
            }
          end
        end
      end
    end
  end
end
