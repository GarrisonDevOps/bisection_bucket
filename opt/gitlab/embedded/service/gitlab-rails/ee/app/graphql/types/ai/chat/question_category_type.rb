# frozen_string_literal: true

module Types
  module Ai
    module Chat
      # rubocop: disable Graphql/AuthorizeTypes -- does not require authorization as these are not user data
      class QuestionCategoryType < Types::BaseObject
        graphql_name 'AiChatQuestionCategory'
        description "Category of suggested questions for GitLab Duo Chat"

        # Only reachable through ContextPreset, which carries no granular
        # authorization of its own; no skip reason describes that, and without
        # a directive tokens deny every category.
        authorize_granular_token skip_reason: :parent_authorizes

        field :key,
          GraphQL::Types::String,
          null: false,
          description: "Stable identifier of the category. `agent` for the agent category, the current " \
            "page type for contextual categories, for example `merge_request` or `blob`, and the topic " \
            "for static ones, for example `security`."

        field :title,
          GraphQL::Types::String,
          null: false,
          description: "Display title of the category, for example the name of the selected agent or " \
            "the reference of the current resource."

        field :contextual,
          GraphQL::Types::Boolean,
          null: false,
          description: "Indicates whether the questions are about the resource on the current page. " \
            "At most one category is contextual, and the agent category, when present, is returned before it."

        field :questions,
          [GraphQL::Types::String],
          null: false,
          description: "Suggested questions in the category."
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
