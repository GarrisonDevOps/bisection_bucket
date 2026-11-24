# frozen_string_literal: true

module EE
  module Types
    module Boards
      module BoardIssueInputBaseType
        extend ActiveSupport::Concern

        prepended do
          argument :epic_id, ::Types::GlobalIDType[::Epic],
            required: false,
            description: 'Filter by epic ID. Incompatible with epicWildcardId.',
            deprecated: { reason: 'This will be replaced by WorkItem hierarchyWidget', milestone: '17.5' }

          argument :iteration_title, GraphQL::Types::String,
            required: false,
            description: 'Filter by iteration title.'

          argument :weight, GraphQL::Types::String,
            required: false,
            description: 'Filter by weight.'

          argument :iteration_id, [::Types::GlobalIDType[::Iteration]],
            required: false,
            description: 'Filter by a list of iteration IDs. Incompatible with iterationWildcardId.'
        end
      end
    end
  end
end
