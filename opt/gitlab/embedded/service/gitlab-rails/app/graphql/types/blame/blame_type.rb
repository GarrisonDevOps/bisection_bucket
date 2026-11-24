# frozen_string_literal: true

module Types
  module Blame
    # rubocop: disable Graphql/AuthorizeTypes
    class BlameType < BaseObject
      # This is presented through `Repository` that has its own authorization
      graphql_name 'Blame'

      present_using Gitlab::BlamePresenter

      authorize_granular_token parent_authorizes: :read_repository_blob

      field :first_line, GraphQL::Types::String, null: true,
        description: 'First line of Git Blame for given range.', calls_gitaly: true
      field :groups, [Types::Blame::GroupsType], null: true,
        description: 'Git Blame grouped by contiguous lines for commit.', calls_gitaly: true,
        method: :groups_commit_data
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
