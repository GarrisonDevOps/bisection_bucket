# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- Same reason as AIMessageExtrasType
    class AdditionalContextType < Types::BaseObject
      graphql_name 'AiAdditionalContext'
      description "Additional context for AI message."

      def self.authorization_scopes
        [:api, :read_api, :ai_features]
      end

      field :category, Types::Ai::AdditionalContextCategoryEnum,
        null: false,
        description: 'Category of the additional context.'

      field :id, GraphQL::Types::ID, # rubocop:disable GraphQL/FieldHashKey -- We want to use the `id` field name https://gitlab.com/gitlab-org/gitlab/-/issues/481548
        null: false,
        description: 'ID of the additional context.'

      field :content, GraphQL::Types::String,
        null: false,
        description: 'Content of the additional context.'

      field :metadata, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- As per discussion on https://gitlab.com/gitlab-org/gitlab/-/issues/481548, we want metadata to be a flexible unstructured field
        null: true,
        description: 'Metadata of the additional context.'

      def id
        object['id']
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
