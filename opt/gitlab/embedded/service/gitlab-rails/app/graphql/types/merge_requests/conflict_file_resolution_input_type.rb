# frozen_string_literal: true

module Types
  module MergeRequests
    class ConflictFileResolutionInputType < BaseInputObject
      graphql_name 'MergeRequestConflictFileResolutionInput'
      description 'Resolution of one file with conflicts: either a side for each conflict, or the resolved content.'

      argument :our_path, GraphQL::Types::String,
        required: true,
        description: 'Path of the file on the source branch, as `ourPath` in `MergeRequest.conflictFiles` returns it.'

      argument :their_path, GraphQL::Types::String,
        required: true,
        description: 'Path of the file on the target branch, as `theirPath` in `MergeRequest.conflictFiles` ' \
          'returns it.'

      argument :sections, [Types::MergeRequests::ConflictSectionResolutionInputType],
        required: false,
        validates: { length: { maximum: Types::BaseArgument::MAX_ARRAY_SIZE } },
        description: 'Side to keep for every conflict in the file. ' \
          "Maximum is #{Types::BaseArgument::MAX_ARRAY_SIZE} sections."

      argument :content, GraphQL::Types::String,
        required: false,
        description: 'Full resolved content of the file.'

      validates exactly_one_of: [:content, :sections]
    end
  end
end
