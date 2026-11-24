# frozen_string_literal: true

module Mutations
  module Snippets
    class Base < BaseMutation
      field :snippet,
        Types::SnippetType,
        null: true,
        description: 'Snippet after mutation.'
    end
  end
end
