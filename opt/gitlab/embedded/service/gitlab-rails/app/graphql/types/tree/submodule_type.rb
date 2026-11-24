# frozen_string_literal: true

module Types
  module Tree
    # rubocop: disable Graphql/AuthorizeTypes
    # This is presented through `Repository` that has its own authorization
    class SubmoduleType < BaseObject
      graphql_name 'Submodule'

      authorize_granular_token parent_authorizes: :read_repository_tree

      implements Types::Tree::EntryType

      field :tree_url, type: GraphQL::Types::String, null: true,
        description: 'Tree URL for the sub-module.'
      field :web_url, type: GraphQL::Types::String, null: true,
        description: 'Web URL for the sub-module.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
