# frozen_string_literal: true

module Types
  module Ai
    class SummarizeNewMergeRequestInputType < BaseMethodInputType
      graphql_name 'AiSummarizeNewMergeRequestInput'
      description "Summarize a new merge request based on two branches. " \
                  "Returns `null` if the `add_ai_summary_for_new_mr` feature flag is disabled."

      argument :source_project_id, ::GraphQL::Types::ID,
        required: false,
        description: 'ID of the project where the changes are from.'

      argument :source_branch, ::GraphQL::Types::String,
        required: true,
        description: 'Source branch of the changes.'

      argument :target_branch, ::GraphQL::Types::String,
        required: true,
        description: 'Target branch of where the changes will be merged into.'
    end
  end
end
