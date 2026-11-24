# frozen_string_literal: true

module Types
  module MergeRequests
    class ConflictSideEnum < BaseEnum
      graphql_name 'MergeRequestConflictSide'
      description 'Side of a conflict to keep.'

      value 'OURS', value: 'head',
        description: 'Keep the lines of the source branch, as `ourLines` of the section lists them.'
      value 'THEIRS', value: 'origin',
        description: 'Keep the lines of the target branch, as `theirLines` of the section lists them.'
    end
  end
end
