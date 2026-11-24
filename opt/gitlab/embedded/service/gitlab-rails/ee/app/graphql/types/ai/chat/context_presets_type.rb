# frozen_string_literal: true

module Types
  module Ai
    module Chat
      # rubocop: disable Graphql/AuthorizeTypes -- does not require authorization as these are not user data
      class ContextPresetsType < Types::BaseObject
        graphql_name 'ContextPreset'
        description "Presets for GitLab Duo Chat window based on current context"

        field :questions,
          [GraphQL::Types::String],
          null: true,
          description: "Array of questions that the user can ask GitLab Duo Chat from the current page."

        field :question_categories,
          [Types::Ai::Chat::QuestionCategoryType],
          null: true,
          experiment: { milestone: '19.4' },
          description: "Suggested questions grouped by category. Not affected by questionCount."

        field :ai_resource_data,
          String,
          null: true,
          description: "Serialized representation of the AI resource in the current context."
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
