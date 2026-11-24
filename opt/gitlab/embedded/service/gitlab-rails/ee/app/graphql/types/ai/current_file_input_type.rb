# frozen_string_literal: true

module Types
  module Ai
    class CurrentFileInputType < BaseInputObject
      graphql_name 'AiCurrentFileInput'

      MAX_FILENAME_SIZE = 1000

      argument :file_name, GraphQL::Types::String,
        required: true,
        description: 'File name.',
        validates: { length: { maximum: MAX_FILENAME_SIZE } }

      argument :selected_text, GraphQL::Types::String,
        required: true,
        description: 'Selected text.',
        validates: { length: { maximum: API::CodeSuggestions::MAX_CONTENT_SIZE } }

      argument :content_above_cursor, GraphQL::Types::String,
        required: false,
        description: 'Content above cursor.',
        validates: { length: { maximum: API::CodeSuggestions::MAX_CONTENT_SIZE } }

      argument :content_below_cursor, GraphQL::Types::String,
        required: false,
        description: 'Content below cursor.',
        validates: { length: { maximum: API::CodeSuggestions::MAX_CONTENT_SIZE } }
    end
  end
end
