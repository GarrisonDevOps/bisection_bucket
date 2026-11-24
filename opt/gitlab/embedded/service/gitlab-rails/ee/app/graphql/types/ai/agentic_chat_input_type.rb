# frozen_string_literal: true

module Types
  module Ai
    class AgenticChatInputType < BaseMethodInputType
      graphql_name 'AiAgenticChatInput'

      argument :content, GraphQL::Types::String,
        required: true,
        validates: { allow_blank: false },
        description: 'Content of the message.'

      argument :namespace_id,
        ::Types::GlobalIDType[::Namespace],
        required: false,
        description: "Global ID of the namespace the user is acting on."

      argument :current_file, ::Types::Ai::CurrentFileInputType,
        required: false,
        description: 'Information about currently selected text which can be passed for additional context.'

      argument :additional_context, [::Types::Ai::AdditionalContextInputType],
        required: false,
        description: 'Additional context to be passed for the chat.'
    end
  end
end
