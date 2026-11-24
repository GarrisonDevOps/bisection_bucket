# frozen_string_literal: true

module Types
  class MergeRequestDiffType < ::Types::BaseObject
    graphql_name 'MergeRequestDiff'
    description 'A diff version of a merge request.'

    authorize :read_merge_request

    authorize_granular_token parent_authorizes: :read_merge_request

    field :created_at, Types::TimeType,
      null: false,
      description: 'Timestamp of when the diff was created.'

    field :updated_at, Types::TimeType,
      null: false,
      description: 'Timestamp of when the diff was updated.'
  end
end
