# frozen_string_literal: true

module Types
  module Analytics
    module CycleAnalytics
      class NegatedIssuableFilterInputType < BaseInputObject
        graphql_name 'NegatedValueStreamAnalyticsIssuableFilterInput'

        argument :assignee_usernames, [GraphQL::Types::String],
          required: false,
          description: 'Usernames of users not assigned to the issue or merge request.'

        argument :author_username, GraphQL::Types::String,
          required: false,
          description: "Username of a user who didn't author the issue or merge request."

        argument :milestone_title, GraphQL::Types::String,
          required: false,
          description: 'Milestone not applied to the issue or merge request.'

        argument :label_names, [GraphQL::Types::String],
          required: false,
          description: 'Labels not applied to the issue or merge request.'

        argument :epic_id, ID,
          required: false,
          description: "ID of an epic not associated with the issues. \
        Using the filter is not supported for stages based on merge requests."

        argument :iteration_id, ID,
          required: false,
          description: "List of iteration Global IDs not applied to the issue. \
        Using the filter is not supported for stages based on merge requests."

        argument :weight, GraphQL::Types::Int,
          required: false,
          description: "Weight not applied to the issue. \
        Using the filter is not supported for stages based on merge requests."

        argument :my_reaction_emoji, GraphQL::Types::String,
          required: false,
          description: Types::Issues::NegatedIssueFilterInputType.arguments['myReactionEmoji'].description
      end
    end
  end
end
