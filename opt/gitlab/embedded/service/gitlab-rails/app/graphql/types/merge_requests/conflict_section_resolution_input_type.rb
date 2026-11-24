# frozen_string_literal: true

module Types
  module MergeRequests
    class ConflictSectionResolutionInputType < BaseInputObject
      graphql_name 'MergeRequestConflictSectionResolutionInput'
      description 'Side to keep for one conflict in a file.'

      argument :section_id, GraphQL::Types::String,
        required: true,
        description: 'ID of the section, as `sectionId` in `MergeRequest.conflictFiles` returns it.'

      argument :resolution, Types::MergeRequests::ConflictSideEnum,
        required: true,
        description: 'Side of the conflict to keep.'
    end
  end
end
